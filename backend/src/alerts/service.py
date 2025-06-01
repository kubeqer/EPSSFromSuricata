import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import List, Optional, Tuple
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import text
from fastapi import BackgroundTasks

from src.config import settings
from src.alerts.models import Alert, AlertStatus, AlertPriority
from src.alerts.schemas import AlertCreate, AlertUpdate, AlertFilter
from src.alerts.constants import (
    EPSS_PRIORITY_THRESHOLDS,
    EMAIL_SUBJECT_TEMPLATE,
    EMAIL_PRIORITY_COLORS,
)
from src.alerts.exceptions import (
    AlertNotFoundException,
    InvalidAlertStatusTransition,
    EmailSendingError,
)
from src.alerts.dependencies import validate_status_transition
from src.suricata.models import SuricataEvent, SuricataCVE
from src.epss.models import CVEScore
from src.pagination import PaginationParams, paginate
from src.suricata.service import SuricataService
from src.epss.service import EPSSService

logger = logging.getLogger(__name__)


class AlertService:
    """Service for handling security alerts"""

    def __init__(
        self,
        db: Session,
        suricata_service: Optional[SuricataService] = None,
        epss_service: Optional[EPSSService] = None,
    ):
        self.db = db
        self.suricata_service = suricata_service or SuricataService(db)
        self.epss_service = epss_service or EPSSService(db)

    async def process_new_events(
        self, background_tasks: BackgroundTasks
    ) -> List[Alert]:
        """
        Process new Suricata events and create alerts
        Returns a list of newly created alerts
        """
        new_events = self.suricata_service.process_new_events()
        if not new_events:
            logger.debug("No new events to process")
            return []
        logger.info(f"Processing {len(new_events)} new events")
        all_cves = set()
        event_cves = {}

        for event in new_events:
            cves = [cve.cve_id for cve in event.cves]
            if cves:
                event_cves[event.id] = cves
                all_cves.update(cves)
        cve_scores = {}
        if all_cves:
            logger.info(f"Fetching EPSS scores for {len(all_cves)} CVEs")
            cve_scores = await self.epss_service.ensure_scores_exist(list(all_cves))
        new_alerts = []
        for event in new_events:
            try:
                event_cves_list = [cve.cve_id for cve in event.cves]
                raw = getattr(event, "raw_event", {}) or {}
                http_block = raw.get("http")
                http_meta = None
                if isinstance(http_block, dict):
                    http_meta = {
                        "url": http_block.get("url"),
                        "method": http_block.get("http_method"),
                        "status": http_block.get("status"),
                        "user_agent": http_block.get("http_user_agent"),
                        "hostname": http_block.get("hostname"),
                        "referrer": http_block.get("http_refer"),
                        "content_type": http_block.get("http_content_type"),
                    }
                    http_meta = {k: v for k, v in http_meta.items() if v is not None}
                is_synthetic = False
                if hasattr(event.raw_event, "get"):
                    is_synthetic = event.raw_event.get("synthetic", False)

                if event_cves_list:
                    highest_cve = None
                    highest_score = -1
                    highest_percentile = -1
                    for cve_id in event_cves_list:
                        if cve_id in cve_scores:
                            score = cve_scores[cve_id]
                            if score.epss_percentile > highest_percentile:
                                highest_cve = cve_id
                                highest_score = score.epss_score
                                highest_percentile = score.epss_percentile
                    if highest_cve:
                        priority = self._determine_priority_for_alert(
                            highest_percentile, event.alert_severity
                        )
                        alert_data = AlertCreate(
                            event_id=event.id,
                            cve_id=highest_cve,
                            epss_score=highest_score,
                            epss_percentile=highest_percentile,
                            priority=priority,
                            http_metadata=http_meta,
                        )

                        alert = self.create_alert(alert_data)
                        new_alerts.append(alert)
                else:
                    priority = self._determine_priority_for_alert(
                        0.0, event.alert_severity
                    )
                    notes = f"No CVE associated. Based on Suricata alert severity: {event.alert_severity}"
                    if is_synthetic and hasattr(event.raw_event, "get"):
                        metadata = event.raw_event.get("alert", {}).get("metadata", {})
                        if isinstance(metadata, dict):
                            patterns = metadata.get("detected_patterns", [])
                            if patterns:
                                notes += f"\n\nDetected patterns: {', '.join(patterns)}"
                            if "http_url" in metadata:
                                notes += f"\n\nURL: {metadata['http_url']}"
                            if "http_user_agent" in metadata:
                                notes += f"\nUser-Agent: {metadata['http_user_agent']}"
                            if "http_status" in metadata:
                                notes += f"\nHTTP Status: {metadata['http_status']}"

                    alert_data = AlertCreate(
                        event_id=event.id,
                        cve_id="N/A",
                        epss_score=0.0,
                        epss_percentile=0.0,
                        priority=priority,
                        notes=notes,
                        http_metadata=http_meta,
                    )
                    alert = self.create_alert(alert_data)
                    new_alerts.append(alert)
                logger.debug(
                    f"Created alert {alert.id} for event {event.id} (priority: {alert.priority.value})"
                )
            except Exception as e:
                logger.error(
                    f"Error creating alert for event {event.id}: {str(e)}",
                    exc_info=True,
                )
                continue
        for event in new_events:
            try:
                self.suricata_service.mark_event_as_processed(event.id)
            except Exception as e:
                logger.error(f"Error marking event {event.id} as processed: {str(e)}")
        if new_alerts:
            logger.info(f"Scheduling email notifications for {len(new_alerts)} alerts")
            background_tasks.add_task(
                self.send_email_notifications, [alert.id for alert in new_alerts]
            )

        logger.info(
            f"Created {len(new_alerts)} new alerts from {len(new_events)} events"
        )
        return new_alerts

    def _determine_priority_from_severity(severity: int) -> AlertPriority:
        """Determine alert priority based on Suricata alert severity"""
        if severity == 1:
            return AlertPriority.HIGH
        elif severity == 2:
            return AlertPriority.MEDIUM
        elif severity == 3:
            return AlertPriority.LOW
        else:
            return AlertPriority.LOW

    def create_alert(self, alert_data: AlertCreate) -> Alert:
        """Create a new alert in the database"""
        try:
            db_alert = Alert(
                event_id=alert_data.event_id,
                cve_id=alert_data.cve_id,
                epss_score=alert_data.epss_score,
                epss_percentile=alert_data.epss_percentile,
                priority=alert_data.priority,
                status=alert_data.status,
                notes=alert_data.notes,
                email_sent=alert_data.email_sent,
                http_metadata=alert_data.http_metadata,
            )
            self.db.add(db_alert)
            self.db.commit()
            self.db.refresh(db_alert)
            logger.debug(
                f"Created alert: {db_alert.id} for event {db_alert.event_id} (priority: {db_alert.priority.value})"
            )
            return db_alert

        except Exception as e:
            self.db.rollback()
            logger.error(f"Error creating alert: {str(e)}", exc_info=True)
            raise

    def get_alert_by_id(self, alert_id: int) -> Alert:
        """Get an alert by ID with event relationship loaded"""
        alert = (
            self.db.query(Alert)
            .options(joinedload(Alert.event))
            .filter(Alert.id == alert_id)
            .first()
        )

        if not alert:
            raise AlertNotFoundException(f"Alert with ID {alert_id} not found")

        return alert

    def update_alert(self, alert_id: int, update_data: AlertUpdate) -> Alert:
        """Update an existing alert"""
        alert = self.get_alert_by_id(alert_id)
        if update_data.status is not None and alert.status != update_data.status:
            if not validate_status_transition(alert.status, update_data.status):
                raise InvalidAlertStatusTransition(
                    f"Invalid status transition from {alert.status.value} to {update_data.status.value}"
                )
        for key, value in update_data.dict(exclude_unset=True).items():
            setattr(alert, key, value)
        alert.updated_at = datetime.utcnow()
        self.db.commit()
        self.db.refresh(alert)
        logger.info(f"Updated alert: {alert.id} (status: {alert.status.value})")
        return alert

    def get_alerts(
        self, filter_params: AlertFilter = None, pagination: PaginationParams = None
    ) -> Tuple[List[Alert], int]:
        """
        Get alerts with filtering and pagination
        Returns a tuple of (alerts, total_count)
        """
        query = self.db.query(Alert).options(joinedload(Alert.event))
        if filter_params:
            if filter_params.status:
                status_values = []
                for status in filter_params.status:
                    if isinstance(status, str):
                        try:
                            status_values.append(AlertStatus(status))
                        except ValueError:
                            logger.warning(f"Invalid status value: {status}")
                    else:
                        status_values.append(status)
                if status_values:
                    query = query.filter(Alert.status.in_(status_values))
            if filter_params.priority:
                priority_values = []
                for priority in filter_params.priority:
                    if isinstance(priority, str):
                        try:
                            priority_values.append(AlertPriority(priority))
                        except ValueError:
                            logger.warning(f"Invalid priority value: {priority}")
                    else:
                        priority_values.append(priority)
                if priority_values:
                    query = query.filter(Alert.priority.in_(priority_values))
            if filter_params.cve_id:
                query = query.filter(Alert.cve_id == filter_params.cve_id)
            if filter_params.start_date:
                query = query.filter(Alert.created_at >= filter_params.start_date)
            if filter_params.end_date:
                query = query.filter(Alert.created_at <= filter_params.end_date)
            if filter_params.is_synthetic is not None:
                query = query.join(SuricataEvent, Alert.event_id == SuricataEvent.id)
                if filter_params.is_synthetic:
                    query = query.filter(
                        text("suricata_events.raw_event::json->>'synthetic' = 'true'")
                    )
                else:
                    query = query.filter(
                        text(
                            "suricata_events.raw_event::json->>'synthetic' IS NULL OR suricata_events.raw_event::json->>'synthetic' != 'true'"
                        )
                    )
        query = query.order_by(Alert.created_at.desc())
        if pagination:
            items, total = paginate(query, pagination)
            return items, total
        else:
            items = query.all()
            return items, len(items)

    def mark_email_sent(self, alert_ids: List[int]) -> None:
        """Mark alerts as having had email notifications sent"""
        self.db.query(Alert).filter(Alert.id.in_(alert_ids)).update(
            {Alert.email_sent: True}, synchronize_session=False
        )
        self.db.commit()
        logger.debug(f"Marked email sent for {len(alert_ids)} alerts")

    async def send_email_notifications(self, alert_ids: List[int]) -> None:
        """Send email notifications for new alerts"""
        if not alert_ids:
            return

        try:
            alerts = (
                self.db.query(Alert)
                .options(joinedload(Alert.event))
                .filter(Alert.id.in_(alert_ids))
                .all()
            )

            if not alerts:
                logger.warning("No alerts found to send notifications for")
                return
            subject = EMAIL_SUBJECT_TEMPLATE.format(alert_count=len(alerts))
            body_html = self._generate_email_html(alerts)
            self._send_email(subject, body_html)
            self.mark_email_sent(alert_ids)
            logger.info(f"Sent email notification for {len(alerts)} alerts")
        except Exception as e:
            logger.error(f"Error sending email notifications: {str(e)}")
            raise EmailSendingError(f"Failed to send email notifications: {str(e)}")

    def _send_email(self, subject: str, body_html: str) -> None:
        """Send an email through SMTP"""
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = settings.EMAILS_FROM_EMAIL
        msg["To"] = settings.EMAILS_TO_EMAIL
        msg.attach(MIMEText(body_html, "html"))

        try:
            server = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT)
            if settings.SMTP_TLS:
                server.starttls()
            if settings.SMTP_USER and settings.SMTP_PASSWORD:
                server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            server.sendmail(
                settings.EMAILS_FROM_EMAIL, settings.EMAILS_TO_EMAIL, msg.as_string()
            )
            server.quit()
            logger.info(f"Successfully sent email to {settings.EMAILS_TO_EMAIL}")

        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"SMTP authentication failed: {str(e)}")
            raise EmailSendingError(f"SMTP authentication failed: {str(e)}")
        except smtplib.SMTPException as e:
            logger.error(f"SMTP error sending email: {str(e)}")
            raise EmailSendingError(f"Failed to send email via SMTP: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error sending email: {str(e)}")
            raise EmailSendingError(f"Failed to send email: {str(e)}")

    def _generate_email_html(self, alerts: List[Alert]) -> str:
        """Generate HTML content for alert email"""
        sorted_alerts = sorted(
            alerts,
            key=lambda a: [
                AlertPriority.CRITICAL,
                AlertPriority.HIGH,
                AlertPriority.MEDIUM,
                AlertPriority.LOW,
            ].index(a.priority),
        )
        html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                .alert-table {{ border-collapse: collapse; width: 100%; }}
                .alert-table th, .alert-table td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                .alert-table tr:nth-child(even) {{ background-color: #f2f2f2; }}
                .alert-table th {{ padding-top: 12px; padding-bottom: 12px; background-color: #4CAF50; color: white; }}
                .priority-critical {{ background-color: {EMAIL_PRIORITY_COLORS["critical"]}; color: white; }}
                .priority-high {{ background-color: {EMAIL_PRIORITY_COLORS["high"]}; color: white; }}
                .priority-medium {{ background-color: {EMAIL_PRIORITY_COLORS["medium"]}; color: black; }}
                .priority-low {{ background-color: {EMAIL_PRIORITY_COLORS["low"]}; color: black; }}
                .synthetic-alert {{ font-style: italic; }}
                .notes {{ font-size: 0.9em; color: #555; white-space: pre-wrap; }}
            </style>
        </head>
        <body>
            <h1>Security Alert Report</h1>
            <p>{len(alerts)} new security alerts have been detected.</p>

            <table class="alert-table">
                <tr>
                    <th>Priority</th>
                    <th>Alert Signature</th>
                    <th>CVE</th>
                    <th>EPSS Score</th>
                    <th>Source IP</th>
                    <th>Destination IP</th>
                    <th>Timestamp</th>
                    <th>Notes</th>
                </tr>
        """

        for alert in sorted_alerts:
            priority_class = f"priority-{alert.priority.value}"
            if alert.cve_id and alert.cve_id != "N/A":
                cve_display = f'<a href="https://nvd.nist.gov/vuln/detail/{alert.cve_id}" target="_blank">{alert.cve_id}</a>'
                epss_percent = f"{alert.epss_percentile:.2f}%"
            else:
                cve_display = "N/A"
                epss_percent = "N/A"
            is_synthetic = ""
            if (
                alert.event
                and hasattr(alert.event, "raw_event")
                and alert.event.raw_event
                and alert.event.raw_event.get("synthetic")
            ):
                is_synthetic = ' <span class="synthetic-alert">(Synthetic)</span>'
            timestamp_str = (
                alert.event.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                if alert.event
                else "N/A"
            )
            notes_text = alert.notes or ""
            html += f"""
                <tr>
                    <td class="{priority_class}">{alert.priority.value.upper()}</td>
                    <td>{alert.event.alert_signature if alert.event else "N/A"}{is_synthetic}</td>
                    <td>{cve_display}</td>
                    <td>{epss_percent}</td>
                    <td>{alert.event.src_ip if alert.event else "N/A"}</td>
                    <td>{alert.event.dest_ip if alert.event else "N/A"}</td>
                    <td>{timestamp_str}</td>
                    <td class="notes">{notes_text}</td>
                </tr>
            """

        html += """
            </table>

            <p>Please investigate these alerts as soon as possible.</p>

            <p><small>Note: Synthetic alerts are generated from suspicious HTTP traffic patterns and may require additional investigation.</small></p>

            <p>This is an automated message. Do not reply to this email.</p>
        </body>
        </html>
        """
        return html

    def _determine_priority(self, epss_percentile: float) -> AlertPriority:
        """Determine alert priority based on EPSS percentile"""
        if epss_percentile <= 1.0:
            epss_percentile = epss_percentile * 100
        if epss_percentile >= EPSS_PRIORITY_THRESHOLDS["critical"]:
            return AlertPriority.CRITICAL
        elif epss_percentile >= EPSS_PRIORITY_THRESHOLDS["high"]:
            return AlertPriority.HIGH
        elif epss_percentile >= EPSS_PRIORITY_THRESHOLDS["medium"]:
            return AlertPriority.MEDIUM
        else:
            return AlertPriority.LOW

    def _determine_priority_for_alert(
        self, epss_percentile: float, suricata_severity: int
    ) -> AlertPriority:
        """
        Determine alert priority based on EPSS score if available, otherwise use Suricata severity
        """
        if epss_percentile > 0:
            return self._determine_priority(epss_percentile)
        else:
            return self._determine_priority_from_severity(suricata_severity)
