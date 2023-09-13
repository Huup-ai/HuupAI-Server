from web3 import Web3

# TODO: Initialize a web3 instance with a BSC node
w3 = Web3(Web3.HTTPProvider(''))
contract_abi = 'YOUR_CONTRACT_ABI_HERE'
contract_address = 'YOUR_CONTRACT_ADDRESS_HERE'

contract = w3.eth.contract(address=contract_address, abi=contract_abi)


def send_transaction(contract, method_name, account, private_key, *args):
    """
    This function sends a transaction to the smart contract
    """
    pass
