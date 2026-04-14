# ============================================================
# Configuration Celery + Beat
# ============================================================

from celery import Celery
from celery.schedules import crontab

celery_app = Celery(
    "cybersentinel",
    broker="redis://redis:6379/0",
    backend="redis://redis:6379/1",
)

celery_app.conf.update(
    timezone="Africa/Casablanca",
    enable_utc=False,
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    beat_schedule={
        "ml-retrain-nightly": {
            "task": "app.services.ml_training.retrain_models",
            "schedule": crontab(hour=2, minute=0),
        }
    },
)
