import json
import os
import re
import sys
from typing import List, Tuple, Optional, Dict, Any

from src.config import BASE_DIFFICULTY



class SerializationUtils:
    @staticmethod
    def save_known_nodes(known_nodes: List[Tuple[str, int]]) -> None:
        with open('data.json', 'w') as f:
            json.dump(known_nodes, f)

    @staticmethod
    def load_known_nodes() -> List[Tuple[str, int]]:
        if os.path.exists('data.json'):
            with open('data.json', 'r') as f:
                return json.load(f)
        return []

    @staticmethod
    def get_last_block(blocks_path: str) -> Optional[Dict]:
        """
        Retrieves the last block from the blocks directory.

        :param blocks_path: The directory where block files are stored.
        :return: The last block as a dictionary, or None if no block is found.
        """
        last_block = max(
            (f for f in os.listdir(blocks_path) if re.match(r'\d+\.json$', f)),
            key=lambda f: int(re.match(r'(\d+)\.json$', f).group(1)),
            default=None
        )
        if last_block is None:
            return None

        with open(os.path.join(blocks_path, last_block), 'r') as f:
            return json.load(f)

    @staticmethod
    def get_blockchain_size(blocks_path: str) -> float:
        """
        Calculate the total size of the blockchain by summing up the size of all files
        in the specified directory.

        Args:
            blocks_path (str): The path to the directory containing blockchain blocks.

        Returns:
            float: The total size of the blockchain in kilobytes (KB).
        """
        total_size = 0
        for dirpath, dirnames, filenames in os.walk(blocks_path):
            for file in filenames:
                file_path = os.path.join(dirpath, file)
                # Ensure the file exists and is not a directory
                if os.path.isfile(file_path):
                    total_size += os.path.getsize(file_path)
        return total_size / 1024  # Convert bytes to kilobytes

    @staticmethod
    def get_block_size(block: Dict) -> float:
        """
        Gets the size of the block without the nonce parameter.

        :param block: The block as a dictionary.
        :return: The size of the block in kilobytes.
        """
        # Remove the 'nonce' parameter if it exists
        block_without_nonce = block.copy()
        block_without_nonce.pop('nonce', None)

        # Convert the block back to a string to calculate its original size
        json_string = json.dumps(block_without_nonce)

        # Calculate the size of the string in bytes
        size_in_bytes = sys.getsizeof(json_string)

        # Convert the size to kilobytes
        return size_in_bytes / 1024

    @staticmethod
    def get_difficulty(blocks_path: str, block: dict) -> int:
        """
        Calculate the difficulty for mining based on the current size of the blockchain
        and the size of the block being added.

        Args:
            blocks_path (str): The path to the directory containing blockchain blocks.
            block (dict): The block for which the difficulty is being calculated.

        Returns:
            int: The calculated difficulty target for mining the block.
        """
        blockchain_size = SerializationUtils.get_blockchain_size(blocks_path)  # Get the size of the blockchain in KB
        block_size = SerializationUtils.get_block_size(block)  # Get the size of the block in bytes
        weight_factor = 0.01  # Factor representing the effect of blockchain size on difficulty
        block_factor = 0.05  # Factor representing the effect of block size on difficulty

        # Calculate new difficulty based on blockchain size and block size
        new_difficulty_target = BASE_DIFFICULTY // (
                int(blockchain_size * weight_factor) + int(block_size * block_factor)
        )

        # Ensure that difficulty does not drop below the minimum allowed value
        min_difficulty_target = 1
        new_difficulty_target = max(min_difficulty_target, new_difficulty_target)

        return int(new_difficulty_target)

    @staticmethod
    def save_block_to_file(data: Dict[str, Any], save_path: str) -> None:
        """
        Saves the given JSON data to a file. The file name will be based on the 'index' value inside the JSON data.

        Parameters:
        data (Dict[str, Any]): The JSON data to be saved. It must contain an 'index' key.
        save_path (str): The directory path where the file should be saved.

        """

        # Convert the index to string to form the filename
        filename = f"{data['index']}.json"

        # Construct the full file path
        file_path = os.path.join(save_path, filename)

        # Write the JSON data to the file
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=4)  # Save with indentation for readability

    @staticmethod
    def get_block(blocks_path: str, index: int) -> Optional[dict]:
        """
        Retrieves a block from the specified directory by its index.

        :param blocks_path: The path to the blocks directory.
        :param index: The index of the block.
        :return: The block as a dictionary if it exists, otherwise None.
        """
        block_file = os.path.join(blocks_path, f"{index}.json")

        # Check if the block file exists
        if os.path.exists(block_file) and os.path.isfile(block_file):
            with open(block_file, 'r') as f:
                return json.load(f)
        else:
            return None
