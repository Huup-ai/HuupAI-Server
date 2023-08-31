
from ..models import *
from ..serializers import *
from datetime import timedelta
from django.utils import timezone


def daily_billing():
    today = timezone.now().date()
    one_month_ago = today - timedelta(days=30)
    
    for user in User.objects.filter(reg_date=today):
        instances = Instance.objects.filter(
            user_id=user,
            status="terminated",
            stop_time=one_month_ago
        )
        
        for instance in instances:
            pricing = instance.pricing_id
            usage_hours = round(instance.usage, 2)
            tax = user.tax
            total_price = round(pricing.price * usage_hours + tax, 2)
            
            # Create an invoice with this data
            invoice_data = {
                'pricing': {
                    'gpus': pricing.gpus,
                    'vram_per_gpu': pricing.vram_per_gpu,
                    'vcpus': pricing.vcpus,
                    'ram': pricing.ram,
                    'storage': pricing.storage,
                    'price': str(pricing.price),
                },
                'usage': usage_hours,
                'tax': tax,
                'total_price': total_price,
            }
            Invoice.objects.create(
                user=user,
                invoice_time=timezone.now(),
                invoice_data=json.dumps(invoice_data)
            )