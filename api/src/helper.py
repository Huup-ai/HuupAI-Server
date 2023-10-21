from ..models import *
from ..serializers import *
from datetime import timedelta
from django.utils import timezone
import requests
from django.core.exceptions import ObjectDoesNotExist

def get_external_api_token(user):
    try:
        url = "https://edgesphereszsciit.com/v3-public/localProviders/local?action=login"
        payload = {
            "username": user.email,
            "password": user.password,
        }
        # send the POST request
        response = requests.post(url, json=payload)

        if response.status_code == 200:
            # extract the token
            cookies = response.headers.get('Set-Cookie')
            if cookies:
                token = cookies.split(';')[0].split('=')[1]
                return token
        else:
            raise Exception
    except Exception as e:
        print(f"An error occurred: {e}")
        return None


def start_instance(user, spec, cluster_id):
    unique_data = {
        'user_id': user,
        'vm_name': spec.get("name"),
        'vm_namespace': spec.get("namespace"),
        'payment_method':spec.get("payment_method")
    }
    try:
        # Find the price from the Pricing table using the cluster_id
        pricing_obj = Pricing.objects.get(cluster_id=cluster_id)
        price = pricing_obj.price
    except ObjectDoesNotExist:
        price=1.0
        print(f"No pricing information found for cluster_id: {cluster_id}, using defualt value 1")
        # return False

    # Default values for creation
    defaults = {
        'status': "started",
        'start_time': timezone.now(),
        'cluster': cluster_id,
        'usage': 0.0,
        'price': price,
        }
    # Merging two dictionaries
    data = {**unique_data, **defaults}

    # Creating an instance with the merged data
    instance = Instance.objects.create(**data)

    return instance


def update_instance(instance, action):
    if instance.status!='terminated':
        instance.status = action
        stop_time = timezone.now()
        instance.usage += (stop_time - instance.start_time).total_seconds() / 3600 # Convert seconds to mins
        if action == 'terminated':
            instance.stop_time = stop_time
        else:
            instance.start_time = timezone.now()
        instance.save()
