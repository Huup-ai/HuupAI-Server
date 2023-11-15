from ..models import *
from ..serializers import *
from datetime import timedelta
from django.utils import timezone
import requests
import boto3
import platform
import os
from botocore.exceptions import ClientError
import subprocess
from django.core.exceptions import ObjectDoesNotExist

def create_instances_helper(num_instances=1):
    # ------ constants
    keypair_name = 'create_ec2'
    keypair_path = f'keys/{keypair_name}.pem'

    # ------ find keypair
    ec2_client = boto3.client('ec2')

    # check if keypair exists on cloud
    try:
        # keypair exist on cloud
        keypairs = ec2_client.describe_key_pairs(
            KeyNames=[
                keypair_name,
            ],
        )

        # private key exist on local
        if not os.path.isfile(keypair_path):
            raise FileNotFoundError(f'{keypair_name} not found in keys')
        return True
    except ClientError as e:
        print(e)
        print('Creating keypair ...')

        # ------ creating keypair
        # create a file to store the key locally
        outfile = open(keypair_path, 'w')

        # call the boto ec2 function to create a key pair
        key_pair = ec2_client.create_key_pair(KeyName=f'{keypair_name}')

        # capture the key and store it in a file
        print(key_pair)
        KeyPairOut = str(key_pair['KeyMaterial'])
        print(KeyPairOut)
        outfile.write(KeyPairOut)

        # ------ chmod 400 <keypair>.pem
        system = platform.system()
        if system == 'Windows':
            # ---- constants
            username = 'Edwar'

            # windows commands for changing mode of a file
            command = f'icacls "{keypair_path}" /inheritance:r /grant:r "{username}:R"'
            try:
                subprocess.run(command, check=True, shell=True)
                print(f'Permissions updated for {keypair_path}')
                return True
            except subprocess.CalledProcessError as e:
                print(f'Error updating permissions: {e}')
        elif system == 'Linux':
            # ---- constants
            permission_value = 0o400

            os.chmod(f'{keypair_path}', permission_value)
            return True
        else:
            raise NameError('platform system unknown')

    # ------ create ec2 instances
    ec2 = boto3.resource('ec2')

    # create a new EC2 instance
    instances = ec2.create_instances(
        ImageId='ami-0e83be366243f524a',  # details in AWS AMI catalog
        MinCount=1,
        MaxCount=num_instances,
        InstanceType='t2.micro',
        KeyName=f'{keypair_name}'
    )

    return instances
def start_instance_helper(instance_id):
    # ------ start instance
    ec2_client = boto3.client('ec2')

    # Do a dryrun first to verify permissions
    try:
        response = ec2_client.start_instances(
            InstanceIds=[
                instance_id
            ],
            DryRun=True
        )
    except ClientError as e:
        if 'DryRunOperation' not in str(e):
            raise

    # Dry run succeeded, run start_instances
    try:
        response = ec2_client.start_instances(
            InstanceIds=[
                instance_id
            ],
            DryRun=False
        )
        print(response)
        return True
    except ClientError as e:
        print(e)
        return False

def stop_instance_helper(instance_id):
    # ------ stop instance
    ec2_client = boto3.client('ec2')

    # Do a dryrun first to verify permissions
    try:
        response = ec2_client.start_instances(
            InstanceIds=[
                instance_id
            ],
            DryRun=True
        )
    except ClientError as e:
        if 'DryRunOperation' not in str(e):
            raise

    # Dry run succeeded, call stop_instances without dryrun
    try:
        response = ec2_client.stop_instances(
            InstanceIds=[
                instance_id
            ],
            DryRun=False
        )
        print(response)
        return True
    except ClientError as e:
        print(e)

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
        'service':spec.get("service")
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
