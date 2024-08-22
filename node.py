import threading
import hashlib
import json
import os
import requests
from typing import List, Tuple

from utils import Utils
from config import GENESIS_BLOCK, BLOCKCHAIN_DIR


class Node:
    def __init__(self, port: int, known_nodes: List[Tuple[str, int]]):
        self.NODE_IP = requests.get('https://checkip.amazonaws.com').text.strip()
        self.NODE_PORT = port
        self.known_nodes = known_nodes.copy()
        self.known_nodes.extend(Utils.load_known_nodes())
        self.known_nodes.append((self.NODE_IP, self.NODE_PORT))
        self.lock = threading.Lock()
        self.genesis_block = GENESIS_BLOCK
        self.blocks_path = BLOCKCHAIN_DIR
        self.setup_blocks()

    def setup_blocks(self):
        if not os.path.exists(self.blocks_path):
            os.makedirs(self.blocks_path)
        if not os.listdir(self.blocks_path):
            block = self.genesis_block
            block_json = json.dumps(block, indent=4)
            file_path = os.path.join(self.blocks_path, str(block['index']) + '.json')

            with open(file_path, 'w') as f:
                f.write(block_json)

    def get_blocks_hash(self) -> str:
        block_files = [f for f in os.listdir(self.blocks_path) if f.endswith('.json')]
        block_files.sort()

        all_blocks_data = ""
        for block_file in block_files:
            with open(os.path.join(self.blocks_path, block_file), 'r') as f:
                block_data = json.load(f)
                all_blocks_data += json.dumps(block_data, sort_keys=True)

        return hashlib.sha256(all_blocks_data.encode('utf-8')).hexdigest()

