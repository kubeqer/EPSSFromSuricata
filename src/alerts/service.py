import logging
import smtplib
import asyncio
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple
from sqlalchemy.orm import Session, joinedload
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
        # Process new events from Suricata
        new_events = self.suricata_service.process_new_events()

        # If no new events, return empty list
        if not new_events:
            return []

        # Extract all CVEs from the new events
        all_cves = set()
        event_cves = {}

        for event in new_events:
            cves = [cve.cve_id for cve in event.cves]
            if cves:
                event_cves[event.id] = cves
                all_cves.update(cves)

        # If no CVEs found, return empty list
        if not all_cves:
            logger.info("No CVEs found in new events, no alerts created")
            return []

        # Get EPSS scores for all CVEs
        cve_scores = await self.epss_service.ensure_scores_exist(list(all_cves))

        # Create alerts for events with CVEs
        new_alerts = []
        for event_id, cves in event_cves.items():
            # For each event, create an alert for the highest-scoring CVE
            if cves:
                # Find highest scoring CVE
                highest_cve = None
                highest_score = -1
                highest_percentile = -1

                for cve_id in cves:
                    if cve_id in cve_scores:
                        score = cve_scores[cve_id]
                        if score.epss_percentile > highest_percentile:
                            highest_cve = cve_id
                            highest_score = score.epss_score
                            highest_percentile = score.epss_percentile

                if highest_cve:
                    # Determine priority based on EPSS percentile
                    priority = self._determine_priority(highest_percentile)

                    # Create alert
                    alert_data = AlertCreate(
                        event_id=event_id,
                        cve_id=highest_cve,
                        epss_score=highest_score,
                        epss_percentile=highest_percentile,
                        priority=priority,
                    )

                    alert = self.create_alert(alert_data)
                    new_alerts.append(alert)

        # Mark events as processed
        for event in new_events:
            self.suricata_service.mark_event_as_processed(event.id)

        # Send email notifications
        if new_alerts:
            background_tasks.add_task(
                self.send_email_notifications, [alert.id for alert in new_alerts]
            )

        logger.info(
            f"Created {len(new_alerts)} new alerts from {len(new_events)} events"
        )
        return new_alerts

    def create_alert(self, alert_data: AlertCreate) -> Alert:
        """Create a new alert in the database"""
        db_alert = Alert(
            event_id=alert_data.event_id,
            cve_id=alert_data.cve_id,
            epss_score=alert_data.epss_score,
            epss_percentile=alert_data.epss_percentile,
            priority=alert_data.priority,
            status=alert_data.status,
            notes=alert_data.notes,
            email_sent=alert_data.email_sent,
        )

        self.db.add(db_alert)
        self.db.commit()
        self.db.refresh(db_alert)

        logger.info(
            f"Created alert: {db_alert.id} for CVE {db_alert.cve_id} (priority: {db_alert.priority.value})"
        )
        return db_alert

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

        # Validate status transition if status is being updated
        if update_data.status is not None and alert.status != update_data.status:
            if not validate_status_transition(alert.status, update_data.status):
                raise InvalidAlertStatusTransition(
                    f"Invalid status transition from {alert.status.value} to {update_data.status.value}"
                )

        # Update fields
        for key, value in update_data.dict(exclude_unset=True).items():
            setattr(alert, key, value)

        # Update timestamp
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

        # Apply filters if provided
        if filter_params:
            if filter_params.status:
                query = query.filter(
                    Alert.status.in_([s for s in filter_params.status])
                )

            if filter_params.priority:
                query = query.filter(
                    Alert.priority.in_([p for p in filter_params.priority])
                )

            if filter_params.cve_id:
                query = query.filter(Alert.cve_id == filter_params.cve_id)

            if filter_params.start_date:
                query = query.filter(Alert.created_at >= filter_params.start_date)

            if filter_params.end_date:
                query = query.filter(Alert.created_at <= filter_params.end_date)

        # Apply default sorting (newest first)
        query = query.order_by(Alert.created_at.desc())

        # Apply pagination if provided
        if pagination:
            items, total = paginate(query, pagination)
            return items, total
        else:
            # If no pagination, get all results
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

            # Create email content
            subject = EMAIL_SUBJECT_TEMPLATE.format(alert_count=len(alerts))
            body_html = self._generate_email_html(alerts)

            # Send email
            self._send_email(subject, body_html)

            # Mark alerts as having had email sent
            self.mark_email_sent(alert_ids)

            logger.info(f"Sent email notification for {len(alerts)} alerts")

        except Exception as e:
            logger.error(f"Error sending email notifications: {str(e)}")
            raise EmailSendingError(f"Failed to send email notifications: {str(e)}")

    def _send_email(self, subject: str, body_html: str) -> None:
        """Send an email"""
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = settings.EMAILS_FROM_EMAIL
        msg["To"] = settings.EMAILS_TO_EMAIL

        # Attach HTML content
        msg.attach(MIMEText(body_html, "html"))

        try:
            # Connect to SMTP server
            if settings.SMTP_TLS:
                server = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT)
                server.starttls()
            else:
                server = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT)

            # Login if credentials provided
            if settings.SMTP_USER and settings.SMTP_PASSWORD:
                server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)

            # Send email
            server.sendmail(
                settings.EMAILS_FROM_EMAIL, settings.EMAILS_TO_EMAIL, msg.as_string()
            )

            # Quit server
            server.quit()

        except Exception as e:
            logger.error(f"Error sending email: {str(e)}")
            raise EmailSendingError(f"Failed to send email: {str(e)}")

    def _generate_email_html(self, alerts: List[Alert]) -> str:
        """Generate HTML content for alert email"""
        # Sort alerts by priority (highest first)
        sorted_alerts = sorted(
            alerts,
            key=lambda a: [
                AlertPriority.CRITICAL,
                AlertPriority.HIGH,
                AlertPriority.MEDIUM,
                AlertPriority.LOW,
            ].index(a.priority),
        )

        # Generate HTML
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
            </style>
        </head>
        <body>
            <h1>Security Alert Report</h1>
            <p>{len(alerts)} new security alerts have been detected.</p>

            <table class="alert-table">
                <tr>
                    <th>Priority</th>
                    <th>CVE</th>
                    <th>EPSS Score</th>
                    <th>Alert Signature</th>
                    <th>Source IP</th>
                    <th>Destination IP</th>
                    <th>Timestamp</th>
                </tr>
        """

        for alert in sorted_alerts:
            priority_class = f"priority-{alert.priority.value}"
            epss_percent = f"{alert.epss_percentile:.2f}%"

            html += f"""
                <tr>
                    <td class="{priority_class}">{alert.priority.value.upper()}</td>
                    <td><a href="https://nvd.nist.gov/vuln/detail/{alert.cve_id}" target="_blank">{alert.cve_id}</a></td>
                    <td>{epss_percent}</td>
                    <td>{alert.event.alert_signature if alert.event else "N/A"}</td>
                    <td>{alert.event.src_ip if alert.event else "N/A"}</td>
                    <td>{alert.event.dest_ip if alert.event else "N/A"}</td>
                    <td>{alert.event.timestamp.strftime("%Y-%m-%d %H:%M:%S") if alert.event else "N/A"}</td>
                </tr>
            """

        html += """
            </table>

            <p>Please investigate these alerts as soon as possible.</p>

            <p>This is an automated message. Do not reply to this email.</p>
        </body>
        </html>
        """

        return html

    def _determine_priority(self, epss_percentile: float) -> AlertPriority:
        """Determine alert priority based on EPSS percentile"""
        if epss_percentile >= EPSS_PRIORITY_THRESHOLDS["critical"]:
            return AlertPriority.CRITICAL
        elif epss_percentile >= EPSS_PRIORITY_THRESHOLDS["high"]:
            return AlertPriority.HIGH
        elif epss_percentile >= EPSS_PRIORITY_THRESHOLDS["medium"]:
            return AlertPriority.MEDIUM
        else:
            return AlertPriority.LOW
