import logging
from typing import Dict, List, Optional, Set
from sqlalchemy.orm import Session

from src.suricata.parser import SuricataParser
from src.suricata.models import SuricataEvent, SuricataCVE
from src.suricata.schemas import SuricataEventCreate
from src.suricata.exceptions import EventNotFoundException

logger = logging.getLogger(__name__)


class SuricataService:
    """Service for handling Suricata events"""

    def __init__(self, db: Session, parser: Optional[SuricataParser] = None):
        self.db = db
        self.parser = parser or SuricataParser()

    def process_new_events(self) -> List[SuricataEvent]:
        """
        Process new events from eve.json and save to database
        Returns a list of newly created events
        """
        new_events = []

        try:
            for raw_event in self.parser.get_new_events():
                parsed_event = self.parser.parse_event(raw_event)

                # Check if event already exists
                existing = (
                    self.db.query(SuricataEvent)
                    .filter_by(event_id=parsed_event["event_id"])
                    .first()
                )

                if existing:
                    logger.debug(
                        f"Event {parsed_event['event_id']} already exists, skipping"
                    )
                    continue

                # Create event data for database
                event_data = SuricataEventCreate(
                    event_id=parsed_event["event_id"],
                    timestamp=parsed_event["timestamp"],
                    src_ip=parsed_event["src_ip"],
                    src_port=parsed_event["src_port"],
                    dest_ip=parsed_event["dest_ip"],
                    dest_port=parsed_event["dest_port"],
                    proto=parsed_event["proto"],
                    alert_signature=parsed_event["alert_signature"],
                    alert_category=parsed_event["alert_category"],
                    alert_severity=parsed_event["alert_severity"],
                    raw_event=parsed_event["raw_event"],
                    cves=parsed_event["cves"],
                )

                # Create and save the event
                db_event = self.create_event(event_data)
                new_events.append(db_event)

            return new_events

        except Exception as e:
            logger.error(f"Error processing Suricata events: {str(e)}")
            raise

    def create_event(self, event_data: SuricataEventCreate) -> SuricataEvent:
        """Create a new Suricata event and associated CVEs in the database"""
        db_event = SuricataEvent(
            event_id=event_data.event_id,
            timestamp=event_data.timestamp,
            src_ip=event_data.src_ip,
            src_port=event_data.src_port,
            dest_ip=event_data.dest_ip,
            dest_port=event_data.dest_port,
            proto=event_data.proto,
            alert_signature=event_data.alert_signature,
            alert_category=event_data.alert_category,
            alert_severity=event_data.alert_severity,
            raw_event=event_data.raw_event,
            processed=False,
        )

        self.db.add(db_event)
        self.db.flush()  # To get the ID

        # Create CVE records
        for cve_id in event_data.cves:
            db_cve = SuricataCVE(event_id=db_event.id, cve_id=cve_id)
            self.db.add(db_cve)

        self.db.commit()
        self.db.refresh(db_event)

        logger.info(
            f"Created Suricata event: {db_event.id} ({db_event.alert_signature})"
        )
        return db_event

    def get_event_by_id(self, event_id: int) -> SuricataEvent:
        """Get a Suricata event by ID"""
        event = (
            self.db.query(SuricataEvent).filter(SuricataEvent.id == event_id).first()
        )
        if not event:
            raise EventNotFoundException(f"Event with ID {event_id} not found")
        return event

    def get_unprocessed_events(self) -> List[SuricataEvent]:
        """Get all unprocessed Suricata events"""
        return (
            self.db.query(SuricataEvent).filter(SuricataEvent.processed == False).all()
        )

    def mark_event_as_processed(self, event_id: int) -> None:
        """Mark a Suricata event as processed"""
        event = self.get_event_by_id(event_id)
        event.processed = True
        self.db.commit()
        logger.debug(f"Marked event {event_id} as processed")
