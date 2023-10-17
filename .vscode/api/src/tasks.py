from celery import shared_task
from .billings import *

@shared_task
def daily_billing_task():
    return daily_billing()