from web3 import Web3
import json
import requests
from celery import shared_task
from api.models import *
from src.helper import *
from django.core.mail import send_mail

@shared_task
def check_instance_status():
    web3 = Web3(Web3.HTTPProvider('https://sepolia.infura.io/v3/e461f10be30a4c31a421c721e8efeac1'))
    
    with open("./resources/contract.abi", "r") as f:
        abi = json.loads(f.read())

    contract_address = '0x2B980535c951fD7B41404196C04Ce3C74775B879'
    contract = web3.eth.contract(address=contract_address, abi=abi)

    wallet_users = Wallet.objects.values_list('user', flat=True)
    instances = Instance.objects.filter(user_id__in=wallet_users)
    
    # Loop through the instances and check their status
    for instance in instances:
        status = contract.functions.getStatus(instance.id).call()
        if status == 0:
            continue
        elif status == 1:
            send_mail(
                'Instance Low Balance Notification',
                'Your instance is ending soon due to low balance',
                'contact@huupai.xyz',
                [instance.user_id.email],
            )
        elif status == 3:
            try:
                response = requests.post('https://your_middleware_domain.com/contract/startrental/', data={'instance_id': instance.id})
                response.raise_for_status()  # This will raise an exception if the response returns an error status code
            except requests.RequestException as e:
                # Handle any error related to the API call here
                print(f"Error stopping rental for instance {instance.id}: {e}")
            
            update_instance(instance,'terminated')
            send_mail(
                'Instance Terminate Notification',
                'Your instance is now been terminated',
                'contact@huupai.xyz',
                [instance.user_id.email],
            )

