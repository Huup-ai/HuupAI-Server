# from __future__ import absolute_import, unicode_literals
# import os
# from celery import Celery, current_app
# from django.conf import settings
# from celery.schedules import crontab

# os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'dummy_api.settings')

# app = Celery('dummy_api')

# app.config_from_object('django.conf:settings', namespace='CELERY')

# app.autodiscover_tasks(lambda: settings.INSTALLED_APPS)

# @current_app.on_after_configure.connect
# def setup_periodic_tasks(sender, **kwargs):
#     # Runs the daily_billing task every day at midnight
#     from api.tasks import daily_billing_task
#     sender.add_periodic_task(
#         crontab(hour=0, minute=0),
#         daily_billing_task.s(),
#     )

#     from api.tasks import check_instance_status
#     # Runs the check_instance_status every hour
#     sender.add_periodic_task(3600.0, check_instance_status.s(), name='Check instance status every hour')
