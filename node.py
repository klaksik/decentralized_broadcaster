import threading
import time
import hashlib
import json
import os
import requests
from typing import List, Tuple
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from utils import Utils
from config import GENESIS_BLOCK, BLOCKCHAIN_DIR, BASE_DIFFICULTY, DIFFICULTY_ADJUSTMENT_INTERVAL, \
    BLOCK_GENERATION_TARGET


class Node:
    def __init__(self, port: int, known_nodes: List[Tuple[str, int]]):
        self.NODE_IP = requests.get('https://checkip.amazonaws.com').text.strip()
        self.NODE_PORT = port
        self.known_nodes = known_nodes.copy()
        self.known_nodes.extend(Utils.load_known_nodes())
        self.known_nodes.append((self.NODE_IP, self.NODE_PORT))
        self.lock = threading.Lock()
        self.difficulty = BASE_DIFFICULTY
        self.genesis_block = GENESIS_BLOCK
        self.blocks_path = BLOCKCHAIN_DIR
        self.setup_blocks()

    def setup_blocks(self):
        if not os.path.exists(self.blocks_path):
            os.makedirs(self.blocks_path)
        if not os.listdir(self.blocks_path):
            self.save_blocks([self.genesis_block])

    def get_blocks(self) -> List[dict]:
        blocks = []
        for block_file in sorted(os.listdir(self.blocks_path)):
            with open(os.path.join(self.blocks_path, block_file), 'r') as f:
                blocks.append(json.load(f))
        return blocks

    def save_blocks(self, blocks: List[dict]) -> None:
        for block in blocks:
            block_data = json.dumps(block).encode('utf-8')
            block_hash = hashlib.sha256(block_data).hexdigest()
            with open(os.path.join(self.blocks_path, block_hash + '.json'), 'w') as f:
                f.write(json.dumps(block))

    def get_blocks_hash(self) -> str:
        block_files = [f for f in os.listdir(self.blocks_path) if f.endswith('.json')]
        block_files.sort()

        all_blocks_data = ""
        for block_file in block_files:
            with open(os.path.join(self.blocks_path, block_file), 'r') as f:
                block_data = json.load(f)
                all_blocks_data += json.dumps(block_data, sort_keys=True)

        return hashlib.sha256(all_blocks_data.encode('utf-8')).hexdigest()

    def validate_block(self, block):
        block_hash = block['hash']
        calculated_hash = Utils.calculate_hash(block)
        if block_hash != calculated_hash:
            return False

        if block['index'] > 0:
            previous_block = self.get_blocks()[block['index'] - 1]
            if block['previous_hash'] != previous_block['hash']:
                return False

        if block['public_key']:
            public_key = RSA.import_key(block['public_key'])
            block_copy = block.copy()
            block_copy['hash'] = ''
            block_copy['data_sign'] = ''
            block_string = json.dumps(block_copy, sort_keys=True).encode()
            h = SHA256.new(block_string)
            try:
                pkcs1_15.new(public_key).verify(h, bytes.fromhex(block['data_sign']))
            except (ValueError, TypeError):
                return False

        difficulty = self.get_difficulty()
        if not self.check_difficulty(block['hash'], difficulty):
            return False

        return True

    def get_difficulty(self) -> int:
        current_time = time.time()
        if current_time - self.last_difficulty_adjustment > DIFFICULTY_ADJUSTMENT_INTERVAL:
            self.adjust_difficulty()
            self.last_difficulty_adjustment = current_time
        return self.difficulty

    def adjust_difficulty(self) -> None:
        blocks = self.get_blocks()
        if len(blocks) < 2:
            return

        last_block_time = blocks[-1]['timestamp']
        time_diff = time.time() - last_block_time
        if time_diff < BLOCK_GENERATION_TARGET:
            self.difficulty += 1
        else:
            self.difficulty = max(BASE_DIFFICULTY, self.difficulty - 1)

    def check_difficulty(self, block_hash, difficulty):
        return block_hash.startswith('0' * difficulty)
