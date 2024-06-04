import hashlib
import json
import time
from typing import Any

class Block:
    def __init__(self, prev_hash: str, data: str, path: str, file_name: str, public_key: str, time_stamp: float = None, nonce: int = 0, data_hash: str = None, data_sign: str = None):
        self.prev_hash = prev_hash
        self.data = data
        self.path = path
        self.file_name = file_name
        self.public_key = public_key
        self.time_stamp = time_stamp or time.time()
        self.nonce = nonce
        self.data_hash = data_hash or self.calculate_hash()
        self.data_sign = data_sign or self.sign_data()

    def calculate_hash(self) -> str:
        hash_data = f"{self.time_stamp}{self.data}{self.path}{self.file_name}{self.nonce}"
        return hashlib.sha256(hash_data.encode()).hexdigest()

    def sign_data(self) -> str:
        # Здесь должна быть реальная подпись данных
        return hashlib.sha256(f"{self.time_stamp}{self.data}{self.path}{self.file_name}".encode()).hexdigest()

    def mine_block(self, difficulty: int):
        required_prefix = '0' * difficulty
        while not self.data_hash.startswith(required_prefix):
            self.nonce += 1
            self.data_hash = self.calculate_hash()

    def __repr__(self) -> str:
        return json.dumps(self.__dict__, indent=4)
