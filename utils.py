import hashlib
import json
import os
import re
import socket
import struct
import random
import sys
import time
from typing import List, Tuple, Dict, Optional, Any

import select
from Crypto.Hash import RIPEMD160
from bech32 import convertbits, bech32_encode
from ecdsa import VerifyingKey, SECP256k1
from ecdsa.util import sigdecode_string
from pydantic import ValidationError

import models
from config import RESPONSE_TIMEOUT, BASE_DIFFICULTY


class Utils:
    @staticmethod
    def create_message(command: str, payload: bytes) -> bytes:
        """
        Creates a message with a header and payload.

        :param command: The command as a string.
        :param payload: The payload as a byte sequence.
        :return: The complete message with header, payload, and checksum.
        """
        # Message header
        header = command.encode('utf-8') + b'\x00' * (12 - len(command))  # Command and padding up to 12 bytes
        length = len(payload)  # Payload length
        header += struct.pack("<I", length)  # Payload length in the header (4 bytes, little-endian)

        # Checksum (first 4 bytes from the hash of header + payload)
        checksum = struct.pack("<I", sum(header + payload) % 2 ** 32)

        # Assembling the message
        message = header + payload + checksum

        return message

    @staticmethod
    def check_checksum(data: bytes) -> bool:
        """
        Verifies the checksum of the message.

        :param data: The complete message as bytes.
        :return: True if the checksum matches, False otherwise.
        """
        header = data[:16]
        command = header[:12].strip(b'\x00').decode('utf-8')  # Extract command from the header
        payload_length = struct.unpack("<I", header[12:16])[0]  # Extract payload length

        if len(data) < 16 + payload_length:
            return False  # If data length is shorter than expected, checksum is invalid

        payload = data[16:16 + payload_length]  # Extract payload
        checksum_received = data[16 + payload_length:20 + payload_length]  # Extract received checksum

        # Calculate the checksum based on the header and payload
        checksum_calculated = struct.pack("<I", sum(header + payload) % 2 ** 32)
        return checksum_received == checksum_calculated  # Compare received and calculated checksums

    @staticmethod
    def parse_addr_payload(payload: bytes) -> List[Tuple[str, int]]:
        """
        Parses the Addr payload and returns a list of addresses.

        :param payload: The payload containing addresses.
        :return: A list of tuples containing IP addresses and ports.
        """
        addresses = []
        num_addresses = struct.unpack("<B", payload[0:1])[0]  # Number of addresses
        index = 1

        for _ in range(num_addresses):
            ip_parts = struct.unpack("<BBBB", payload[index:index + 4])  # Unpack IP address
            ip = ".".join(map(str, ip_parts))  # Convert IP parts to string
            port = struct.unpack(">H", payload[index + 4:index + 6])[0]  # Unpack port
            addresses.append((ip, port))  # Add address to the list
            index += 6  # Move index to the next IP and port
            index += 4  # Skip 4 bytes for timestamp

        return addresses

    @staticmethod
    def create_addr_payload(addresses: List[Tuple[str, int]]) -> bytes:
        """
        Creates an Addr payload, limiting it to 100 addresses.

        :param addresses: A list of tuples containing IP addresses and ports.
        :return: The created Addr payload as bytes.
        """
        if len(addresses) > 100:
            addresses = random.sample(addresses, 100)  # Select 100 random addresses

        payload = b""
        payload += struct.pack("<B", len(addresses))  # Number of addresses

        for addr, port in addresses:
            ip_parts = list(map(int, addr.split('.')))
            payload += struct.pack("<BBBB", *ip_parts)  # IP address
            payload += struct.pack(">H", port)  # Port (2 bytes)
            payload += struct.pack("<I", int(time.time()))  # Timestamp in seconds since the Unix epoch

        return payload

    @staticmethod
    def save_known_nodes(known_nodes: List[Tuple[str, int]]) -> None:
        """
        Saves known_nodes to a data.json file in JSON format.

        :param known_nodes: A list of known nodes (IP address, port).
        """
        with open('data.json', 'w') as f:
            json.dump(known_nodes, f)

    @staticmethod
    def load_known_nodes() -> List[Tuple[str, int]]:
        """
        Loads known_nodes from the data.json file, if the file exists.

        :return: A list of known nodes (IP address, port), or an empty list if the file does not exist.
        """
        if os.path.exists('data.json'):
            with open('data.json', 'r') as f:
                return json.load(f)
        return []

    @staticmethod
    def calculate_hash(block: Dict) -> str:
        """
        Calculates the SHA-256 hash of a block.

        :param block: The block as a dictionary.
        :return: The hash of the block as a hexadecimal string.
        """
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

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
    def check_difficulty(block_hash: str, difficulty: int) -> bool:
        """
        Checks if the block hash meets the difficulty requirement.

        :param block_hash: The block hash as a hexadecimal string.
        :param difficulty: The difficulty level (number of leading zeros).
        :return: True if the block hash satisfies the difficulty, False otherwise.
        """
        return block_hash.startswith('0' * difficulty)

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
    def get_new_block(self, conn):
        try:
            # Request the next block
            conn.sendall(Utils.create_message(
                command="getnextblock",
                payload=(Utils.get_last_block(self.node.blocks_path).get('index')).encode("utf-8")))

            # Use select to set a timeout for the response
            ready_to_read, _, _ = select.select([conn], [], [], RESPONSE_TIMEOUT)

            if ready_to_read:
                response = conn.recv(1024)
                header = response[:16]
                command = header[:12].strip(b'\x00').decode('utf-8')
                payload_length = struct.unpack("<I", header[12:16])[0]

                if len(response) < 16 + payload_length:
                    Utils.remove_node(self, conn)

                payload = response[16:16 + payload_length]
                checksum_received = response[16 + payload_length:20 + payload_length]

                # Verify checksum
                checksum_calculated = struct.pack("<I", sum(header + payload) % 2 ** 32)
                if checksum_received != checksum_calculated:
                    print("Checksum mismatch")
                    Utils.remove_node(self, conn)

                if command == "nextblock":
                    # Process the received next block
                    next_block = json.loads(payload.decode('utf-8'))
                    if Utils.validate_block(blocks_path=self.node.blocks_path, block=next_block):
                        Utils.save_block_to_file(data=next_block, save_path=self.node.blocks_path)
                        print("Block successfully added to the blockchain.")
                    else:
                        print("Invalid block received.")
                elif command == "nonexistentblock":
                    print("Requested block does not exist.")
                    Utils.remove_node(self, conn)
                    return False
            else:
                print("No response, closing connection.")
                Utils.remove_node(self, conn)

        except (socket.error, OSError, BrokenPipeError) as e:
            print(f"Error with connection: {e}")
            Utils.remove_node(self, conn)

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
        blockchain_size = Utils.get_blockchain_size(blocks_path)  # Get the size of the blockchain in KB
        block_size = Utils.get_block_size(block)  # Get the size of the block in bytes
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
            prev_block_json = Utils.get_last_block(blocks_path)

            # Validate the previous block's hash and index continuity.
            if block['previous_hash'] != prev_block_json['hash'] or block['index'] != prev_block_json['index'] + 1:
                return False

        # Ensure that the block's public key hash matches the derived P2WPKH format.
        if block['hash_pubkey'] != Utils.pubkey_to_p2wpkh(block['pubkey']):
            return False

        # Verify the block's digital signature using the block's public key and its signed data.
        if not Utils.verify_signature(
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
        difficulty = Utils.get_difficulty(blocks_path, block)
        if not Utils.check_difficulty(block['hash'], difficulty):
            return False

        # All checks passed; the block is valid.
        return True

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

    @staticmethod
    def remove_node(self, conn: socket.socket) -> None:
        """
        Removes a node from the client_connections and known_nodes lists and closes the connection.

        :param conn: The socket connection associated with the node.
        """
        node = (conn.getpeername()[0], conn.getpeername()[1])  # Retrieve the IP and port of the peer

        if node in self.known_nodes:
            self.known_nodes.remove(node)  # Remove the node from known_nodes list
            Utils.save_known_nodes(self.known_nodes)  # Save the updated known_nodes list to a file

        if conn in self.client_connections:
            self.client_connections.remove(conn)  # Remove the connection from client_connections list
        conn.close()  # Close the connection

    @staticmethod
    def check_node_working(node_ip: str, node_port: int, check_node: Tuple[str, int]) -> bool:
        """
        Checks if a node is active by sending a PING message and waiting for a PONG response.

        :param node_ip: The IP address of the node to be checked.
        :param node_port: The port number of the node to be checked.
        :param check_node: The IP and port of the node to check in a tuple format.
        :return: True if the node responds with a PONG, False otherwise.
        """
        try:
            # Establish a connection to the node
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
                conn.settimeout(5)  # Set a timeout of 5 seconds for the connection
                conn.connect(check_node)  # Connect to the node

                # Create a payload consisting of the node's IP and port
                ip_bytes = socket.inet_aton(node_ip)
                port_bytes = struct.pack("<H", node_port)
                payload = ip_bytes + port_bytes

                # Send a handshake message to the node
                conn.sendall(Utils.create_message("handshake", payload))

                # Receive the response from the node
                response = conn.recv(1024)

                # Check if the checksum is valid
                if not Utils.check_checksum(response):
                    print("Checksum mismatch")
                    return False

                # Parse the response header to extract the command and payload length
                header = response[:16]
                command = header[:12].strip(b'\x00').decode('utf-8')
                payload_length = struct.unpack("<I", header[12:16])[0]

                # Verify if the response has a valid payload length
                if len(response) < 16 + payload_length:
                    return False

                # Check if the command is an 'addr' response
                if command == "addr":
                    return True

        except (socket.timeout, socket.error) as e:
            print(f"Failed to connect to {check_node}: {e}")

        return False

    @staticmethod
    def create_handshake_message(ip: str, port: int) -> bytes:
        """
        Creates a handshake message consisting of the IP address and port number.

        :param ip: The IP address as a string.
        :param port: The port number as an integer.
        :return: A byte sequence representing the handshake message.
        """
        ip_bytes = socket.inet_aton(ip)  # Convert the IP address to a byte sequence
        port_bytes = struct.pack("<H", port)  # Pack the port as a 2-byte integer (little-endian)
        return b"handshake" + struct.pack("<I", len(ip_bytes + port_bytes)) + ip_bytes + port_bytes
