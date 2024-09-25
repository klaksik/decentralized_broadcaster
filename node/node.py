import threading
import json
import os
import requests
from typing import List, Tuple
import socket

from src.utils import SerializationUtils
from src.config import GENESIS_BLOCK, BLOCKCHAIN_DIR


class Node:
    def __init__(self, port: int, known_nodes: List[Tuple[str, int]]):
        self.NODE_IP = requests.get('https://checkip.amazonaws.com').text.strip()
        self.NODE_PORT = port
        self.known_nodes = known_nodes.copy()
        self.known_nodes.extend(SerializationUtils.load_known_nodes())
        self.known_nodes.append((self.NODE_IP, self.NODE_PORT))
        self.lock = threading.Lock()
        self.genesis_block = GENESIS_BLOCK
        self.blocks_path = BLOCKCHAIN_DIR
        self.setup_blocks()
        self.client_connections: List[socket.socket] = []
        self.server_connections: List[socket.socket] = []

    def setup_blocks(self):
        if not os.path.exists(self.blocks_path):
            os.makedirs(self.blocks_path)
        if not os.listdir(self.blocks_path):
            block = self.genesis_block
            block_json = json.dumps(block, indent=4)
            file_path = os.path.join(self.blocks_path, str(block['index']) + '.json')

            with open(file_path, 'w') as f:
                f.write(block_json)
