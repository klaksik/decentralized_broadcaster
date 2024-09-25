import hashlib
import json
import re
import sys
import os
from typing import Dict, Optional, Any

from pydantic import ValidationError

from src import models
from src.utils import HashingUtils, SerializationUtils


class ValidationUtils:
    @staticmethod
    def verify_signature(public_key_hex: str, signature_hex: str, message: str) -> bool:
        from ecdsa import VerifyingKey, SECP256k1
        from ecdsa.util import sigdecode_string
        public_key_bytes = bytes.fromhex(public_key_hex)
        signature_bytes = bytes.fromhex(signature_hex)
        message_bytes = message.encode('utf-8')
        verifying_key = VerifyingKey.from_string(public_key_bytes, curve=SECP256k1)
        return verifying_key.verify(sigdecode_string(signature_bytes, SECP256k1.order, 'ecdsa'), message_bytes)

    @staticmethod
    def get_block_size(block: Dict) -> float:
        block_without_nonce = block.copy()
        block_without_nonce.pop('nonce', None)
        json_string = json.dumps(block_without_nonce)
        size_in_bytes = sys.getsizeof(json_string)
        return size_in_bytes / 1024

    @staticmethod
    def get_last_block(blocks_path: str) -> Optional[Dict]:
        last_block = max(
            (f for f in os.listdir(blocks_path) if re.match(r'\\d+\\.json$', f)),
            key=lambda f: int(re.match(r'(\\d+)\\.json$', f).group(1)),
            default=None
        )
        if last_block is None:
            return None

        with open(os.path.join(blocks_path, last_block), 'r') as f:
            return json.load(f)
    @staticmethod
    def validate_block(blocks_path: str, block: Dict[str, Any]) -> bool:
        """
        Validates the given block by checking its structure, previous block hash, signature,
        and difficulty.

        Parameters:
        blocks_path: The directory where block files are stored.
        block (Dict[str, Any]): The block to be validated, containing keys like 'index',
                                'previous_hash', 'timestamp', 'data', 'pubkey', 'data_sign', etc.

        Returns:
        bool: True if the block is valid, False otherwise.
        """
        try:
            # Attempt to validate the block structure by converting it into a BlockModel.
            # BlockModel is assumed to be a Pydantic model that enforces schema validation.
            models.BlockModel(**block)
        except ValidationError:
            # If the block does not conform to the model's schema, it is invalid.
            return False

        # If the block index is greater than 0, check the previous block's hash and index.
        if block['index'] > 0:
            # Retrieve the previous block as a JSON object.
            prev_block_json = ValidationUtils.get_last_block(blocks_path)

            # Validate the previous block's hash and index continuity.
            if block['previous_hash'] != prev_block_json['hash'] or block['index'] != prev_block_json['index'] + 1:
                return False

        # Ensure that the block's public key hash matches the derived P2WPKH format.
        if block['hash_pubkey'] != HashingUtils.pubkey_to_p2wpkh(block['pubkey']):
            return False

        # Verify the block's digital signature using the block's public key and its signed data.
        if not HashingUtils.verify_signature(
                public_key_hex=block['pubkey'],
                signature_hex=block['data_sign'],
                message=(
                        str(block['index'])
                        + str(block['previous_hash'])
                        + str(block['timestamp'])
                        + str(block['data'])
                        + str(block['path'])
                        + str(block['file_name'])
                        + str(block['pubkey'])
                        + str(block['hash_pubkey'])
                )
        ):
            return False

        # Recalculate the block's hash and compare it to the provided hash value.
        recalculated_hash = hashlib.sha256((
                                                   str(block['index'])
                                                   + str(block['previous_hash'])
                                                   + str(block['timestamp'])
                                                   + str(block['data'])
                                                   + str(block['nonce'])
                                                   + str(block['path'])
                                                   + str(block['file_name'])
                                                   + str(block['pubkey'])
                                                   + str(block['hash_pubkey'])
                                                   + str(block['data_sign'])
                                           ).encode('utf-8')).hexdigest()

        if block['hash'] != recalculated_hash:
            return False

        # Check if the block's hash satisfies the required mining difficulty.
        difficulty = SerializationUtils.get_difficulty(blocks_path, block)
        if not HashingUtils.check_difficulty(block['hash'], difficulty):
            return False

        # All checks passed; the block is valid.
        return True