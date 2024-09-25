import json
import socket
import struct
from typing import Tuple

import select

from src.config import RESPONSE_TIMEOUT
from src.utils import NetworkingUtils, SerializationUtils, ValidationUtils


class NodeUtils:
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
                conn.sendall(NetworkingUtils.create_message("handshake", payload))

                # Receive the response from the node
                response = conn.recv(1024)

                # Check if the checksum is valid
                if not NetworkingUtils.check_checksum(response):
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

    @staticmethod
    def get_new_block(self, conn):
        try:
            # Request the next block
            conn.sendall(NetworkingUtils.create_message(
                command="getnextblock",
                payload=(SerializationUtils.get_last_block(self.node.blocks_path).get('index')).encode("utf-8")))

            # Use select to set a timeout for the response
            ready_to_read, _, _ = select.select([conn], [], [], RESPONSE_TIMEOUT)

            if ready_to_read:
                response = conn.recv(1024)
                header = response[:16]
                command = header[:12].strip(b'\x00').decode('utf-8')
                payload_length = struct.unpack("<I", header[12:16])[0]

                if len(response) < 16 + payload_length:
                    NetworkingUtils.remove_node(self, conn)

                payload = response[16:16 + payload_length]
                checksum_received = response[16 + payload_length:20 + payload_length]

                # Verify checksum
                checksum_calculated = struct.pack("<I", sum(header + payload) % 2 ** 32)
                if checksum_received != checksum_calculated:
                    print("Checksum mismatch")
                    NetworkingUtils.remove_node(self, conn)

                if command == "nextblock":
                    # Process the received next block
                    next_block = json.loads(payload.decode('utf-8'))
                    if ValidationUtils.validate_block(blocks_path=self.node.blocks_path, block=next_block):
                        SerializationUtils.save_block_to_file(data=next_block, save_path=self.node.blocks_path)
                        print("Block successfully added to the blockchain.")
                    else:
                        print("Invalid block received.")
                elif command == "nonexistentblock":
                    print("Requested block does not exist.")
                    NetworkingUtils.remove_node(self, conn)
                    return False
            else:
                print("No response, closing connection.")
                NetworkingUtils.remove_node(self, conn)

        except (socket.error, OSError, BrokenPipeError) as e:
            print(f"Error with connection: {e}")
            NetworkingUtils.remove_node(self, conn)