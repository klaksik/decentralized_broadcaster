import json
import os
from typing import List
from block import Block

class Blockchain:
    def __init__(self, filename="blockchain.json"):
        self.chain: List[Block] = []
        self.filename = filename
        self.load_blockchain()

    def create_genesis_block(self):
        genesis_block = Block("0", "Genesis Block", "", "", "public_key")
        genesis_block.mine_block(difficulty=2)
        self.chain.append(genesis_block)
        self.save_blockchain()

    def add_block(self, block: Block):
        if self.is_valid(block):
            self.chain.append(block)
            self.save_blockchain()
            self.logger.debug(f"Block added: {block}")
            if self.debug:
                print(f"Block added: {block}")
        else:
            self.logger.warning("Attempted to add invalid block to blockchain")
            if self.debug:
                print("Attempted to add invalid block to blockchain")

    def is_valid(self, block: Block) -> bool:
        # Проверяем целостность блока
        if block.prev_hash != self.chain[-1].data_hash:
            return False
        # Проверяем правильность хеша блока
        if block.data_hash != block.calculate_hash():
            return False
        return True

    def save_blockchain(self):
        with open(self.filename, 'w') as f:
            json.dump([block.__dict__ for block in self.chain], f, indent=4)

    def load_blockchain(self):
        if os.path.exists(self.filename):
            with open(self.filename, 'r') as f:
                blocks = json.load(f)
                self.chain = [Block(**block) for block in blocks]
        else:
            self.create_genesis_block()

    def __repr__(self):
        return json.dumps([block.__dict__ for block in self.chain], indent=4)
