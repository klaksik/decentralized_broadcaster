import socket
import struct
import threading
from typing import Tuple, List
from utils import Utils
from node import Node
from config import MAX_CONNECTIONS
import json


class Server:
    def __init__(self, node: Node):
        self.node = node
        self.server_connections: List[socket.socket] = []

    def handle_client(self, conn: socket.socket, addr: Tuple[str, int]) -> None:
        print(f"Connected by {addr}")
        data = conn.recv(1024)
        if data:
            command = data[:12].decode('utf-8').strip('\x00')
            if command == "handshake":
                payload_length = struct.unpack("<I", data[12:16])[0]
                payload = data[16:16 + payload_length]
                if len(payload) == 6:
                    ip_bytes = payload[:4]
                    port_bytes = payload[4:]
                    nodeip = socket.inet_ntoa(ip_bytes)
                    port = struct.unpack("<H", port_bytes)[0]
                    if (nodeip, port) not in self.node.known_nodes:
                        self.node.known_nodes.append((nodeip, port))
                        Utils.save_known_nodes(self.node.known_nodes)

        response_payload = Utils.create_addr_payload(self.node.known_nodes)
        response_message = Utils.create_message("addr", response_payload)
        conn.sendall(response_message)

        if len(self.server_connections) >= MAX_CONNECTIONS:
            conn.close()
            return

        self.server_connections.append(conn)
        try:
            while True:
                data = conn.recv(1024)
                if not data:
                    continue

                if not Utils.check_checksum(data):
                    print("Checksum mismatch")
                    continue

                header = data[:16]
                command = header[:12].strip(b'\x00').decode('utf-8')

                if command == "getaddr":
                    response_payload = Utils.create_addr_payload(self.node.known_nodes)
                    conn.sendall(Utils.create_message("addr", response_payload))
                    print(f"Received addresses: {response_payload}")

                elif command == "ping":
                    conn.sendall(Utils.create_message("pong", b""))
                    print(f"Received ping: pong")

                elif command == "getblockshash":
                    blocks_hash = self.node.get_blocks_hash().encode('utf-8')
                    conn.sendall(Utils.create_message("blockshash", blocks_hash))
                    print(f"Sent blocks hash: {blocks_hash.decode('utf-8')}")

                elif command == "getblocks":
                    blocks = self.node.get_blocks()
                    blocks_data = json.dumps(blocks).encode('utf-8')
                    conn.sendall(Utils.create_message("blocks", blocks_data))
                    print(f"Sent blocks: {blocks}")

                elif command == "block":
                    payload_length = struct.unpack("<I", header[12:16])[0]
                    if len(data) < 16 + payload_length:
                        continue

                    payload = data[16:16 + payload_length]
                    block = json.loads(payload.decode('utf-8'))
                    if self.node.validate_block(block):
                        self.node.save_blocks([block])
                        self.node.last_block_time = block['timestamp']
                        print(f"Block validated and saved: {block}")
                    else:
                        print(f"Invalid block received: {block}")

                elif command == "difficulty":
                    difficulty = struct.unpack("<I", data[16:20])[0]
                    self.node.difficulty = difficulty
                    print(f"Difficulty updated: {difficulty}")

        except socket.timeout:
            print("Client connection timed out.")
        finally:
            conn.close()

    def start_server(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.node.NODE_IP, self.node.NODE_PORT))
            s.listen()
            print(f"Server started on {self.node.NODE_IP}:{self.node.NODE_PORT}")
            while True:
                conn, addr = s.accept()
                threading.Thread(target=self.handle_client, args=(conn, addr)).start()
