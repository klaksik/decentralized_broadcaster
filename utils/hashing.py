import hashlib
import json
import os
from typing import Dict

from Crypto.Hash import RIPEMD160
from bech32 import convertbits, bech32_encode
from ecdsa import VerifyingKey, SECP256k1
from ecdsa.util import sigdecode_string


class HashingUtils:

    @staticmethod
    def get_blocks_hash(blocks_path: str) -> str:
        block_files = [f for f in os.listdir(blocks_path) if f.endswith('.json')]
        block_files.sort()

        all_blocks_data = ""
        for block_file in block_files:
            with open(os.path.join(blocks_path, block_file), 'r') as f:
                block_data = json.load(f)
                all_blocks_data += json.dumps(block_data, sort_keys=True)

        return hashlib.sha256(all_blocks_data.encode('utf-8')).hexdigest()

    @staticmethod
    def calculate_hash(block: Dict) -> str:
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    @staticmethod
    def pubkey_to_p2wpkh(public_key_hex: str) -> str:
        """
        Converts a public key to a P2WPKH (Bech32) address.

        :param public_key_hex: The public key in hexadecimal format.
        :return: The corresponding P2WPKH Bech32 address.
        """
        public_key_bytes = bytes.fromhex(public_key_hex)

        # Hash the public key: first SHA256, then RIPEMD160
        sha256_hash = hashlib.sha256(public_key_bytes).digest()
        ripemd160_hash = RIPEMD160.new(sha256_hash).digest()

        # Add 0x00 prefix for P2WPKH
        p2wpkh_payload = ripemd160_hash

        # Convert to 5-bit groups
        data = convertbits(p2wpkh_payload, 8, 5)

        # Create Bech32 address with 'bc' prefix
        hrp = 'bc'
        bech32_address = bech32_encode(hrp, data)

        return bech32_address

    @staticmethod
    def verify_signature(public_key_hex: str, signature_hex: str, message: str) -> bool:
        """
        Verifies a signature using the public key.

        :param public_key_hex: The public key in hexadecimal format.
        :param signature_hex: The signature in hexadecimal format.
        :param message: The message that was signed.
        :return: True if the signature is valid, False otherwise.
        """
        public_key_bytes = bytes.fromhex(public_key_hex)
        r = bytes.fromhex(signature_hex[:64])
        s = bytes.fromhex(signature_hex[64:])
        signature_bytes = r + s
        message_bytes = message.encode()

        verifying_key = VerifyingKey.from_string(public_key_bytes, curve=SECP256k1)
        try:
            verifying_key.verify(signature_bytes, message_bytes, sigdecode=sigdecode_string)
            return True
        except Exception:
            return False

    @staticmethod
    def check_difficulty(block_hash: str, difficulty: int) -> bool:
        """
        Checks if the block hash meets the difficulty requirement.

        :param block_hash: The block hash as a hexadecimal string.
        :param difficulty: The difficulty level (number of leading zeros).
        :return: True if the block hash satisfies the difficulty, False otherwise.
        """
        return block_hash.startswith('0' * difficulty)