from web3 import Web3
import json
from celery import shared_task
from api.models import *
from django.core.mail import send_mail

# TODO: Initialize a web3 instance with a BSC node
web3 = Web3(Web3.HTTPProvider('https://sepolia.infura.io/v3/e461f10be30a4c31a421c721e8efeac1'))

# Replace with your contract's ABI and address
with open("./resources/contract.abi", "r") as f:
  abi = json.loads(f.read())

contract_address = '0x74334a9Ca8601d75072acD5d37E69a6a12F22cdf'

contract = web3.eth.contract(address=contract_address, abi=abi)

@shared_task
def check_instance_status():
    web3 = Web3(Web3.HTTPProvider('https://sepolia.infura.io/v3/e461f10be30a4c31a421c721e8efeac1'))
    
    with open("./resources/contract.abi", "r") as f:
        abi = json.loads(f.read())

    contract_address = '0x74334a9Ca8601d75072acD5d37E69a6a12F22cdf'
    contract = web3.eth.contract(address=contract_address, abi=abi)
    
    # Retrieve list of instances from your Django model
    instances = Instance.objects.all()
    # Loop through the instances and check their status
    for instance in instances:
        status = contract.functions.getStatus(instance.id).call()
        if status == 0:
            pass
        elif status == 1:
            pass
        elif status == 3:
            # Call another API to block chain to stop instance 
            # and call your own stop VM to update database
            pass

