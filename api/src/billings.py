
from ..models import *
from ..serializers import *
from datetime import timedelta
from django.utils import timezone
from django.db import transaction
import json


def daily_billing():
    today = timezone.now().date()
    one_month_ago = today - timedelta(days=30)
    
    for user in User.objects.filter(invoice_date=one_month_ago):
        instances = Instance.objects.filter(user_id=user)
        
        to_update_instances = []
        
        with transaction.atomic():
            for instance in instances:
                try:
                    new_usage = instance.usage
                    if instance.status != 'terminated':
                        time_delta = timezone.now() - instance.start_time
                        new_usage += time_delta.total_seconds() / 3600  # Calculate usage in hours

                    usage_hours = round(new_usage, 2)
                    tax = user.tax
                    total_price = round(instance.price * usage_hours + tax, 2)
                    
                    # Create an invoice with this data
                    invoice_data = {
                        'price': str(instance.price),
                        'usage': usage_hours,
                        'tax': tax,
                        'total_price': total_price,
                    }
                    Invoice.objects.create(
                        user_id=user,
                        invoice_time=timezone.now(),
                        invoice_data=json.dumps(invoice_data)
                    )
                    instance.usage = 0.0
                    instance.start_time = timezone.now()
                    to_update_instances.append(instance)
                except Exception as e:
                    # Handle exception appropriately (Logging recommended)
                    print(f"Error processing instance ID {instance.id}: {e}")
            
            Instance.objects.bulk_update(to_update_instances, ['usage', 'start_time'])
            user.invoice_date = today
            user.save()