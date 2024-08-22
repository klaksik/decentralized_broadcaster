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

                elif command == "getnextblock":
                    try:
                        payload_length = struct.unpack("<I", header[12:16])[0]
                        if len(data) < 16 + payload_length:
                            continue

                        payload = data[16:16 + payload_length]

                        index = payload.decode('utf-8')
                        next_block = Utils.get_block(blocks_path=self.node.blocks_path, index=int(index)+1)

                        if next_block:
                            next_block_data = json.dumps(next_block).encode('utf-8')
                            conn.sendall(Utils.create_message("nextblock", next_block_data))
                            print(f"Sent next block: {next_block}")
                        else:
                            conn.sendall(Utils.create_message("nonexistentblock", b""))
                    except Exception as e:
                        print(f"Error handling getnextblock: {e}")

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
