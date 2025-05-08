import asyncio
import logging
from fastapi import FastAPI, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from sqlalchemy.orm import Session

from src.database import Base, engine, get_db
from src.config import settings
from src.exceptions import register_exception_handlers
from src.alerts.router import router as alerts_router
from src.alerts.service import AlertService

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)
Base.metadata.create_all(bind=engine)


async def periodic_alert_check(app: FastAPI):
    """Periodically check for new Suricata events and create alerts"""
    while True:
        try:
            from src.database import get_db_context

            with get_db_context() as db:
                background_tasks = BackgroundTasks()
                service = AlertService(db)
                new_alerts = await service.process_new_events(background_tasks)

                if new_alerts:
                    logger.info(
                        f"Background task: Created {len(new_alerts)} new alerts"
                    )
            await background_tasks()

        except Exception as e:
            logger.error(f"Error in periodic alert check: {str(e)}")
        await asyncio.sleep(settings.SURICATA_POLL_INTERVAL)


background_tasks = set()


@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(periodic_alert_check(app))
    background_tasks.add(task)
    logger.info(
        f"Started background task to check for alerts every {settings.SURICATA_POLL_INTERVAL} seconds"
    )
    yield
    for task in background_tasks:
        task.cancel()
    logger.info("Shutting down background tasks")


app = FastAPI(
    title=settings.PROJECT_NAME,
    description="API for monitoring Suricata alerts with EPSS scoring",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


register_exception_handlers(app)
app.include_router(alerts_router, prefix=settings.API_V1_STR)


@app.get("/")
async def root():
    return {"name": settings.PROJECT_NAME, "version": "0.1.0", "status": "operational"}


@app.get("/health")
async def health_check():
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("src.main:app", host="0.0.0.0", port=8000, reload=True)
