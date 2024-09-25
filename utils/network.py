import json
import random
import socket
import struct
import time
from typing import List, Tuple

import select

from src.config import RESPONSE_TIMEOUT
from src.utils import SerializationUtils


class NetworkingUtils:

    @staticmethod
    def send_new_block(block, node):
        for conn in node.client_connections:
            with node.lock:
                # Request block hash from the connection
                conn.sendall(NetworkingUtils.create_message("newblock", json.dumps(block).encode('utf-8')))

                # Use select to set a timeout for the response
                ready_to_read, _, _ = select.select([conn], [], [], RESPONSE_TIMEOUT)

                if ready_to_read:
                    response = conn.recv(1024)
                    header = response[:16]
                    command = header[:12].strip(b'\x00').decode('utf-8')
                    payload_length = struct.unpack("<I", header[12:16])[0]

                    if len(response) < 16 + payload_length:
                        continue

                    payload = response[16:16 + payload_length]
                    checksum_received = response[16 + payload_length:20 + payload_length]

                    # Verify checksum
                    checksum_calculated = struct.pack("<I", sum(header + payload) % 2 ** 32)
                    if checksum_received != checksum_calculated:
                        print("Checksum mismatch")
                        continue

                    if command == "ack":
                        print("Acknowledging block.")
                    elif command == "reject":
                        print("Requested block does not exist.")

    @staticmethod
    def create_message(command: str, payload: bytes) -> bytes:
        # Message header
        header = command.encode('utf-8') + b'\x00' * (12 - len(command))
        length = len(payload)
        header += struct.pack("<I", length)

        # Checksum
        checksum = struct.pack("<I", sum(header + payload) % 2 ** 32)

        # Assembling the message
        message = header + payload + checksum

        return message

    @staticmethod
    def check_checksum(data: bytes) -> bool:
        # Verifies the checksum of the message.
        header = data[:16]
        if len(header) < 16:
            return False
        payload_length = struct.unpack("<I", header[12:16])[0]
        if len(data[16:]) < payload_length:
            return False

        checksum = struct.unpack("<I", data[-4:])[0]
        return (sum(data[:-4]) % (2 ** 32)) == checksum

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
    def remove_node(self, conn: socket.socket) -> None:
        """
        Removes a node from the client_connections and known_nodes lists and closes the connection.

        :param conn: The socket connection associated with the node.
        """
        node = (conn.getpeername()[0], conn.getpeername()[1])  # Retrieve the IP and port of the peer

        if node in self.known_nodes:
            self.known_nodes.remove(node)  # Remove the node from known_nodes list
            SerializationUtils.save_known_nodes(self.known_nodes)  # Save the updated known_nodes list to a file

        if conn in self.client_connections:
            self.client_connections.remove(conn)  # Remove the connection from client_connections list
        conn.close()  # Close the connection

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