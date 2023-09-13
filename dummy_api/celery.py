from __future__ import absolute_import, unicode_literals
import os
from celery import Celery, current_app
from django.conf import settings
from celery.schedules import crontab
from api.src.tasks import daily_billing

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'BACKEND_API.settings')

app = Celery('BACKEND_API')

app.config_from_object('django.conf:settings', namespace='CELERY')

app.autodiscover_tasks(lambda: settings.INSTALLED_APPS)

@current_app.on_after_configure.connect
def setup_periodic_tasks(sender, **kwargs):
    # Runs the daily_billing task every day at midnight
    sender.add_periodic_task(
        crontab(hour=0, minute=0),
        daily_billing.s(),
    )