from ..models import *
from ..serializers import *
from datetime import timedelta
from django.utils import timezone

def determin_price_id(spec):
    #TODO: CHANGE TO ACTUAL PRICE
    return '1'

def start_instance(user, spec, cluster_id):
    unique_data = {
    'user_id': user,
    'vm_id': spec.get("id"),
    'vm_name': spec.get("name"),
    'vm_namespace': spec.get("namespace"),
}

# Default values for creation
    defaults = {
        'pricing_id': determin_price_id(spec),
        'status': "started",
        'start_time': timezone.now(),
        'cluster': cluster_id,
        'usage': 0.0  # initial value, this can be updated later as per your requirements
    }

    instance, created = Instance.objects.update_or_create(defaults=defaults, **unique_data)
    return True

def update_instance(instance, action):
    instance.status = action
    stop_time = timezone.now()
    instance.usage += (stop_time - instance.start_time).total_seconds() / 60 # Convert seconds to mins
    instance.stop_time = stop_time
    instance.save()
