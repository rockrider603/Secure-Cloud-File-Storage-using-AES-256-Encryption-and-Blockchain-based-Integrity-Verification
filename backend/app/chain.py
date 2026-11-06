import json
from pathlib import Path
from web3 import Web3
from .config import settings

ABI = [
 {"inputs":[{"internalType":"bytes32","name":"fileId","type":"bytes32"},{"internalType":"bytes32","name":"versionId","type":"bytes32"},{"internalType":"bytes32","name":"digest","type":"bytes32"}],"name":"registerVersion","outputs":[],"stateMutability":"nonpayable","type":"function"},
 {"inputs":[{"internalType":"bytes32","name":"fileId","type":"bytes32"},{"internalType":"bytes32","name":"versionId","type":"bytes32"}],"name":"getVersion","outputs":[{"internalType":"bytes32","name":"digest","type":"bytes32"},{"internalType":"uint64","name":"timestamp","type":"uint64"},{"internalType":"bool","name":"exists","type":"bool"}],"stateMutability":"view","type":"function"}
]
def configured():
    if not settings.chain_contract_address: raise RuntimeError("Integrity registry is not configured")
    w3 = Web3(Web3.HTTPProvider(settings.chain_rpc_url, request_kwargs={"timeout": 4}))
    if not w3.is_connected() or w3.eth.chain_id != settings.chain_id: raise RuntimeError("Configured integrity chain is unavailable or has the wrong network ID")
    return w3, w3.eth.contract(address=Web3.to_checksum_address(settings.chain_contract_address), abi=ABI)
def ids(file_id: str, version_id: str): return (Web3.keccak(text=file_id), Web3.keccak(text=version_id))
def register(file_id: str, version_id: str, digest: str):
    w3, contract = configured()
    if not settings.chain_private_key: raise RuntimeError("Chain writer is not configured")
    account = w3.eth.account.from_key(settings.chain_private_key)
    f, v = ids(file_id, version_id)
    tx = contract.functions.registerVersion(f, v, bytes.fromhex(digest)).build_transaction({"from": account.address, "nonce": w3.eth.get_transaction_count(account.address), "chainId": settings.chain_id, "gas": 250000, "gasPrice": w3.eth.gas_price})
    signed = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=30)
    if receipt.status != 1: raise RuntimeError("Integrity registration transaction reverted")
    return tx_hash.hex(), receipt.blockNumber
def read(file_id: str, version_id: str):
    w3, contract = configured()
    f, v = ids(file_id, version_id)
    digest, timestamp, exists = contract.functions.getVersion(f, v).call()
    return (digest.hex(), timestamp) if exists else None
