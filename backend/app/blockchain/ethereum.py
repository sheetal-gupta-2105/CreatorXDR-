
import json
import os
from pathlib import Path

from web3 import Web3


class EthereumClient:
    """Manages the connection between CreatorXDR and the Ethereum network."""

    def __init__(self):
        self.rpc_url = os.getenv(
            "BLOCKCHAIN_RPC_URL",
            "http://host.docker.internal:8545",
        )

        self.expected_chain_id = int(
            os.getenv("BLOCKCHAIN_CHAIN_ID", "31337")
        )

        private_key = os.getenv("BLOCKCHAIN_PRIVATE_KEY")
        contract_address = os.getenv("BLOCKCHAIN_CONTRACT_ADDRESS")

        if not private_key:
            raise RuntimeError("BLOCKCHAIN_PRIVATE_KEY is not configured.")

        if not contract_address:
            raise RuntimeError("BLOCKCHAIN_CONTRACT_ADDRESS is not configured.")

        # Establish RPC connection.
        self.w3 = Web3(
            Web3.HTTPProvider(
                self.rpc_url,
                request_kwargs={"timeout": 15},
            )
        )

        if not self.w3.is_connected():
            raise ConnectionError(
                f"Unable to connect to Ethereum RPC: {self.rpc_url}"
            )

        # Verify that we are connected to the expected network.
        self.chain_id = self.w3.eth.chain_id

        if self.chain_id != self.expected_chain_id:
            raise RuntimeError(
                f"Wrong Ethereum network. "
                f"Expected chain ID {self.expected_chain_id}, "
                f"received {self.chain_id}."
            )

        # Load the signing account.
        self.account = self.w3.eth.account.from_key(private_key)

        # Validate and checksum the contract address.
        if not Web3.is_address(contract_address):
            raise ValueError("Invalid blockchain contract address.")

        self.contract_address = Web3.to_checksum_address(
            contract_address
        )

        # Load the contract ABI.
        abi_path = (
            Path(__file__).resolve().parent
            / "abi"
            / "CreatorXDRAnchor.json"
        )

        if not abi_path.exists():
            raise FileNotFoundError(
                f"Contract ABI not found: {abi_path}"
            )

        with abi_path.open("r", encoding="utf-8") as abi_file:
            self.abi = json.load(abi_file)

        # Verify that contract bytecode exists at this address.
        contract_code = self.w3.eth.get_code(self.contract_address)

        if not contract_code:
            raise RuntimeError(
                "No contract deployed at "
                f"{self.contract_address} on chain {self.chain_id}."
            )

        # Initialize the contract interface.
        self.contract = self.w3.eth.contract(
            address=self.contract_address,
            abi=self.abi,
        )

    def get_connection_info(self):
        """Return safe connection details. Never expose the private key."""
        return {
            "connected": self.w3.is_connected(),
            "chain_id": self.chain_id,
            "account_address": self.account.address,
            "contract_address": self.contract_address,
            "contract_version": self.contract.functions.CONTRACT_VERSION().call(),
        }


def get_ethereum_client():
    """Create and return an Ethereum client."""
    return EthereumClient()
