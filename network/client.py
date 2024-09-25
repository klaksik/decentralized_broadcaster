import random
import socket
import threading
import struct
import time
import select

from src.node.node import Node
from src.config import MAX_CONNECTIONS, MIN_CONNECTIONS, RESPONSE_TIMEOUT, CONNECT_INTERVAL, PING_INTERVAL, \
    UPDATE_NODES_INTERVAL, UPDATE_BLOCKCHAIN_INTERVAL
from src.utils import NetworkingUtils, SerializationUtils, NodeUtils, HashingUtils


class Client:

    def __init__(self, node: Node):
        self.node = node

    def connect_to_nodes(self) -> None:
        """
        Подключается к другим узлам и обрабатывает ответ в соответствии с ограничениями.
        """
        while True:
            print("server_connections " + str(self.node.client_connections))
            print("known_nodes" + str(self.node.known_nodes))
            if len(self.node.client_connections) >= MAX_CONNECTIONS:
                pass
            elif len(self.node.client_connections) < MIN_CONNECTIONS:
                known_nodes = tuple([x for x in self.node.known_nodes if x != (self.node.NODE_IP, self.node.NODE_PORT)])
                current_node = None
                for n in known_nodes:

                    if not self.node.client_connections:
                        current_node = n
                        break

                    for j in self.node.client_connections:
                        try:
                            if n != j.getpeername():
                                current_node = n
                                break
                        except (OSError, BrokenPipeError):
                            pass

                if current_node:

                    print("node" + str(current_node))
                    conn = None
                    try:
                        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        conn.settimeout(5)
                        conn.connect(tuple(current_node))

                        ip_bytes = socket.inet_aton(self.node.NODE_IP)
                        port_bytes = struct.pack("<H", self.node.NODE_PORT)
                        payload = ip_bytes + port_bytes

                        conn.sendall(NetworkingUtils.create_message("handshake", payload))

                        response = conn.recv(1024)
                        if not NetworkingUtils.check_checksum(response):
                            print("Checksum mismatch")
                            conn.close()
                            continue

                        header = response[:16]
                        command = header[:12].strip(b'\x00').decode('utf-8')
                        payload_length = struct.unpack("<I", header[12:16])[0]

                        if len(response) < 16 + payload_length:
                            continue

                        payload = response[16:16 + payload_length]

                        if command == "addr":
                            addresses = NetworkingUtils.parse_addr_payload(payload)
                            # Update known node, limiting to 100 addresses
                            if len(addresses) < 100:
                                for addr in addresses:
                                    if addr not in self.node.known_nodes:
                                        if NodeUtils.check_node_working(self.node.NODE_IP, self.node.NODE_PORT, addr):
                                            self.node.known_nodes.append(addr)
                                            SerializationUtils.save_known_nodes(self.node.known_nodes)  # Сохраняем изменения

                            else:
                                conn.close()
                                if current_node in self.node.known_nodes:
                                    self.node.known_nodes.remove(current_node)
                                    SerializationUtils.save_known_nodes(self.node.known_nodes)  # Сохраняем изменения
                                break

                        try:
                            # Отправка PING
                            conn.sendall(NetworkingUtils.create_message("ping", b""))

                            # Использование select для установки таймаута
                            ready_to_read, _, _ = select.select([conn], [], [], RESPONSE_TIMEOUT)

                            if ready_to_read:
                                response = conn.recv(1024)
                                if not NetworkingUtils.check_checksum(response):
                                    print("Checksum mismatch")
                                    if current_node in self.node.known_nodes:
                                        self.node.known_nodes.remove(current_node)
                                        SerializationUtils.save_known_nodes(self.node.known_nodes)  # Сохраняем изменения
                                    continue

                                header = response[:16]
                                command = header[:12].strip(b'\x00').decode('utf-8')

                                if command == "pong":
                                    print(f"Connection established. {current_node}")
                                    self.node.client_connections.append(conn)

                        except socket.timeout:
                            print(f"Connection to {current_node} timed out.")
                            conn.close()
                            if current_node in self.node.known_nodes:
                                self.node.known_nodes.remove(current_node)
                                SerializationUtils.save_known_nodes(self.node.known_nodes)  # Сохраняем изменения

                    except Exception as e:
                        print(f"Failed to connect to {current_node}: {e}")
                        if conn:
                            conn.close()
                        if current_node in self.node.known_nodes:
                            self.node.known_nodes.remove(current_node)
                            SerializationUtils.save_known_nodes(self.node.known_nodes)  # Сохраняем изменения

            time.sleep(CONNECT_INTERVAL)

    def ping_nodes(self) -> None:
        """
        Отправляет ping сообщения всем подключенным узлам и обрабатывает их ответы.
        Если узел не отвечает в течение времени таймаута или возникает ошибка, он удаляется из списка узлов.
        """
        while True:
            with self.node.lock:
                current_connections = self.node.client_connections[:]
                for conn in current_connections:
                    try:
                        # Отправка PING
                        conn.sendall(NetworkingUtils.create_message("ping", b""))

                        # Использование select для установки таймаута
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

                            # Проверяем контрольную сумму
                            checksum_calculated = struct.pack("<I", sum(header + payload) % 2 ** 32)
                            if checksum_received != checksum_calculated:
                                print("Checksum mismatch")
                                continue

                            if command == "pong":
                                print("Received pong")
                            else:
                                print(f"Unexpected response: {payload.decode('utf-8')}")
                                NetworkingUtils.remove_node(self, conn)
                        else:
                            print("No response, closing connection.")
                            NetworkingUtils.remove_node(self, conn)

                    except (socket.error, OSError, BrokenPipeError) as e:
                        print(f"Error with connection: {e}")
                        NetworkingUtils.remove_node(self, conn)

            time.sleep(PING_INTERVAL)

    def update_nodes_list(self) -> None:
        """
        Получает список узлов и добавляет их в known_nodes, исключая дубликаты.
        Использует таймаут для ожидания ответа и обрабатывает исключения.
        """
        while True:
            with self.node.lock:
                current_connections = self.node.client_connections[:]
                for conn in current_connections:
                    try:
                        # Запрос списка узлов
                        conn.sendall(NetworkingUtils.create_message("getaddr", b""))

                        # Использование select для установки таймаута
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

                            # Проверяем контрольную сумму
                            checksum_calculated = struct.pack("<I", sum(header + payload) % 2 ** 32)
                            if checksum_received != checksum_calculated:
                                print("Checksum mismatch")
                                continue

                            if command == "addr":
                                # Парсинг пейлоада для извлечения узлов
                                nodes = NetworkingUtils.parse_addr_payload(payload)

                                # Обновление known_nodes, исключая дубликаты и ограничивая до 100 узлов
                                for n in nodes:
                                    if n not in self.node.known_nodes:
                                        if len(self.node.known_nodes) < 100:
                                            self.node.known_nodes.append(n)
                                        else:
                                            break
                                print(f"Updated known_nodes: {self.node.known_nodes}")
                        else:
                            print("No response, closing connection.")
                            NetworkingUtils.remove_node(self, conn)

                    except (socket.error, OSError, BrokenPipeError) as e:
                        print(f"Error with connection: {e}")
                        NetworkingUtils.remove_node(self, conn)
            time.sleep(UPDATE_NODES_INTERVAL)

    def update_blockchain(self) -> None:
        """
        Continuously checks for discrepancies between the local blockchain and the majority blockchain hash.
        If a majority hash differs from the local hash, attempts to update the blockchain by retrieving the next block.
        """
        while True:
            # Get your own blockchain's hash
            own_blocks_hash = HashingUtils.get_blocks_hash(self.node.blocks_path)

            # Dictionary to count the occurrences of each hash received from other node
            hash_counts = {}
            hash_connections = {}  # Track which connections sent each hash

            with self.node.lock:
                current_connections = self.node.client_connections[:]
                for conn in current_connections:
                    try:
                        # Request block hash from the connection
                        conn.sendall(NetworkingUtils.create_message("getblockshash", b""))

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

                            if command == "blockshash":
                                # Process the received blocks hash
                                received_hash = payload.decode('utf-8')
                                print(f"Received blocks hash: {received_hash}")

                                # Update hash counts
                                if received_hash in hash_counts:
                                    hash_counts[received_hash] += 1
                                    hash_connections[received_hash].append(conn)
                                else:
                                    hash_counts[received_hash] = 1
                                    hash_connections[received_hash] = [conn]

                        else:
                            print("No response, closing connection.")
                            NetworkingUtils.remove_node(self, conn)

                    except (socket.error, OSError, BrokenPipeError) as e:
                        print(f"Error with connection: {e}")
                        NetworkingUtils.remove_node(self, conn)

                # Determine the majority hash and its count
                if hash_counts:
                    majority_hash, majority_count = max(hash_counts.items(), key=lambda item: item[1])
                    total_hashes = sum(hash_counts.values())

                    # Check if the majority is at least 51%
                    if majority_count >= total_hashes * 0.51:
                        if majority_hash != own_blocks_hash:
                            print("Majority of node have a different blockchain. Updating blockchain.")

                            # Only keep connections that sent the majority hash
                            majority_connections = hash_connections[majority_hash]

                            while majority_hash != HashingUtils.get_blocks_hash(self.node.blocks_path):
                                with self.node.lock:
                                    if majority_connections:
                                        conn = random.choice(majority_connections)
                                        res = NodeUtils.get_new_block(self, conn)
                                        if not res:
                                            majority_connections.remove(conn)
                                    else:
                                        break
                        else:
                            print("No need to update blockchain. Local blockchain matches majority.")

            time.sleep(UPDATE_BLOCKCHAIN_INTERVAL)

    def start_client(self) -> None:
        threading.Thread(target=self.connect_to_nodes()).start()
        threading.Thread(target=self.ping_nodes()).start()
        threading.Thread(target=self.update_nodes_list()).start()
