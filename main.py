import time
import hashlib
import json
import os
import requests
import socket
import struct
import threading
from typing import List, Tuple
import select
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Utils import Utils

# Конфигурация узла
NODE_PORT = 25496
MAX_CONNECTIONS = 12
MIN_CONNECTIONS = 6
PING_INTERVAL = 120
UPDATE_INTERVAL = 200
RESPONSE_TIMEOUT = 5
CONNECT_INTERVAL = 10
GENESIS_BLOCK = {
    "index": 0,
    "previous_hash": "0",
    "timestamp": 0,
    "data": "Genesis Block",
    "nonce": 0,
    "path": "",
    "file_name": "",
    "public_key": "",
    "data_sign": "",
    "hash": "0"
}

BLOCKCHAIN_DIR = "blockchain"
BASE_DIFFICULTY = 4
DIFFICULTY_ADJUSTMENT_INTERVAL = 600  # Интервал для корректировки сложности в секундах
BLOCK_GENERATION_TARGET = 10  # Целевое время генерации блока в секундах


class Node:
    def __init__(self, port: int, known_nodes: List[Tuple[str, int]]):
        self.NODE_IP = requests.get('https://checkip.amazonaws.com').text.strip()
        self.NODE_PORT = port
        self.known_nodes = known_nodes.copy()
        self.known_nodes.append((self.NODE_IP, self.NODE_PORT))
        self.server_connections: List[socket.socket] = []
        self.client_connections: List[socket.socket] = []
        self.lock = threading.Lock()
        self.difficulty = BASE_DIFFICULTY  # Начальная сложность
        self.last_block_time = time.time()
        self.last_difficulty_adjustment = time.time()  # Добавляем атрибут для последней регулировки сложности
        self.genesis_block = GENESIS_BLOCK
        self.blocks_path = BLOCKCHAIN_DIR  # Путь к папке для хранения блоков
        self.setup_blocks()

    def setup_blocks(self):
        # Убедитесь, что папка существует
        if not os.path.exists(self.blocks_path):
            os.makedirs(self.blocks_path)
        # Создайте генезис блок, если блокчейн пуст
        if not os.listdir(self.blocks_path):
            self.save_blocks([self.genesis_block])

    def calculate_hash(self, block):
        """Вычисляет хеш блока."""
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def get_blocks(self) -> List[dict]:
        """Возвращает все блоки в виде списка словарей."""
        blocks = []
        for block_file in sorted(os.listdir(self.blocks_path)):
            with open(os.path.join(self.blocks_path, block_file), 'r') as f:
                blocks.append(json.load(f))
        return blocks

    def save_blocks(self, blocks: List[dict]) -> None:
        """Сохраняет блоки в файловую систему."""
        for block in blocks:
            block_data = json.dumps(block).encode('utf-8')
            block_hash = hashlib.sha256(block_data).hexdigest()
            with open(os.path.join(self.blocks_path, block_hash + '.json'), 'w') as f:
                f.write(json.dumps(block))

    def get_blocks_hash(self) -> str:
        """Возвращает хэш всех блоков в блокчейне."""
        block_files = [f for f in os.listdir(self.blocks_path) if f.endswith('.json')]
        block_files.sort()  # Сортируем файлы по имени, предполагая, что имена содержат индексы блоков

        all_blocks_data = ""
        for block_file in block_files:
            with open(os.path.join(self.blocks_path, block_file), 'r') as f:
                block_data = json.load(f)
                all_blocks_data += json.dumps(block_data, sort_keys=True)

        return hashlib.sha256(all_blocks_data.encode('utf-8')).hexdigest()

    def validate_block(self, block):
        """Валидирует блок."""
        block_hash = block['hash']
        calculated_hash = self.calculate_hash(block)
        if block_hash != calculated_hash:
            return False

        if block['index'] > 0:
            previous_block = self.get_blocks()[block['index'] - 1]
            if block['previous_hash'] != previous_block['hash']:
                return False

        if block['public_key']:
            public_key = RSA.import_key(block['public_key'])
            block_copy = block.copy()
            block_copy['hash'] = ''
            block_copy['data_sign'] = ''
            block_string = json.dumps(block_copy, sort_keys=True).encode()
            h = SHA256.new(block_string)
            try:
                pkcs1_15.new(public_key).verify(h, bytes.fromhex(block['data_sign']))
            except (ValueError, TypeError):
                return False

        # Проверка сложности
        difficulty = self.get_difficulty()
        if not self.check_difficulty(block['hash'], difficulty):
            return False

        return True

    def get_difficulty(self) -> int:
        """Возвращает текущее значение сложности."""
        current_time = time.time()
        if current_time - self.last_difficulty_adjustment > DIFFICULTY_ADJUSTMENT_INTERVAL:
            self.adjust_difficulty()
            self.last_difficulty_adjustment = current_time
        return self.difficulty

    def adjust_difficulty(self) -> None:
        """Корректирует сложность на основе времени генерации блоков."""
        blocks = self.get_blocks()
        if len(blocks) < 2:
            return

        last_block_time = blocks[-1]['timestamp']
        time_diff = time.time() - last_block_time
        if time_diff < BLOCK_GENERATION_TARGET:
            self.difficulty += 1
        else:
            self.difficulty = max(BASE_DIFFICULTY, self.difficulty - 1)

    def check_difficulty(self, block_hash, difficulty):
        """Проверяет, соответствует ли хеш блока сложности."""
        return block_hash.startswith('0' * difficulty)

    class Server:
        def __init__(self, node):
            self.node = node

        def handle_client(self, conn: socket.socket, addr: Tuple[str, int]) -> None:
            print(f"Connected by {addr}")
            data = conn.recv(1024)
            if data:
                command = data[:12].decode('utf-8').strip('\x00')
                if command == "handshake":
                    payload_length = struct.unpack("<I", data[12:16])[0]
                    payload = data[16:16 + payload_length]
                    if len(payload) == 6:  # IP (4 байта) + порт (2 байта)
                        ip_bytes = payload[:4]
                        port_bytes = payload[4:]
                        nodeip = socket.inet_ntoa(ip_bytes)
                        port = struct.unpack("<H", port_bytes)[0]
                        if (nodeip, port) not in node.known_nodes:
                            node.known_nodes.append((nodeip, port))
                            Utils.save_known_nodes(node.known_nodes)

            if len(node.server_connections) >= MAX_CONNECTIONS:
                response_payload = Utils.create_addr_payload(node.known_nodes)
                response_message = Utils.create_message("addr", response_payload)
                conn.sendall(response_message)
                conn.close()
                return

            else:
                response_payload = Utils.create_addr_payload(node.known_nodes)
                response_message = Utils.create_message("addr", response_payload)
                conn.sendall(response_message)

            node.server_connections.append(conn)
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
                        response_payload = Utils.create_addr_payload(node.known_nodes)
                        conn.sendall(Utils.create_message("addr", response_payload))
                        print(f"Received addresses: {response_payload}")

                    elif command == "ping":
                        conn.sendall(Utils.create_message("pong", b""))
                        print(f"Received ping: pong")

                    elif command == "getblockshash":
                        blocks_hash = node.get_blocks_hash().encode('utf-8')
                        conn.sendall(Utils.create_message("blockshash", blocks_hash))
                        print(f"Sent blocks hash: {blocks_hash.decode('utf-8')}")

                    elif command == "getblocks":
                        blocks = node.get_blocks()
                        blocks_data = json.dumps(blocks).encode('utf-8')
                        conn.sendall(Utils.create_message("blocks", blocks_data))
                        print(f"Sent blocks: {blocks}")

                    elif command == "block":
                        payload_length = struct.unpack("<I", header[12:16])[0]
                        if len(data) < 16 + payload_length:
                            continue

                        payload = data[16:16 + payload_length]
                        block = json.loads(payload.decode('utf-8'))
                        if node.validate_block(block):
                            node.save_blocks([block])
                            node.last_block_time = block['timestamp']
                            print(f"Block validated and saved: {block}")
                        else:
                            print(f"Invalid block received: {block}")

                    elif command == "difficulty":
                        difficulty = struct.unpack("<I", data[16:20])[0]
                        node.difficulty = difficulty
                        print(f"Difficulty updated: {difficulty}")

            except socket.timeout:
                print("Client connection timed out.")
            finally:
                conn.close()

        def start_server(self) -> None:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind((node.NODE_IP, node.NODE_PORT))
                s.listen()
                print(f"Server listening on {node.NODE_IP}:{node.NODE_PORT}")
                while True:
                    conn, addr = s.accept()
                    threading.Thread(target=self.handle_client, args=(conn, addr)).start()

    class Client:
        def __init__(self, node):
            self.node = node

        def connect_to_nodes(self) -> None:
            """
            Подключается к другим узлам и обрабатывает ответ в соответствии с ограничениями.
            """
            while True:
                print("server_connections " + str(node.server_connections) + " client_connections " + str(
                    node.client_connections))
                print("known_nodes" + str(node.known_nodes))
                if len(node.client_connections) < MIN_CONNECTIONS:
                    known_nodes = tuple(node.known_nodes)
                    current_node = None
                    for n in known_nodes:
                        # Skip the current node
                        if n == (node.NODE_IP, node.NODE_PORT):
                            continue

                        if not node.client_connections:
                            current_node = n
                            break

                        for j in node.client_connections:
                            try:
                                if n != j.getpeername():
                                    current_node = n
                                    break
                            except (OSError, BrokenPipeError):
                                pass

                        if current_node is None:
                            time.sleep(CONNECT_INTERVAL)
                            continue

                    if current_node:

                        print("node" + str(current_node))
                        conn = None
                        try:
                            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            conn.settimeout(5)
                            conn.connect(tuple(current_node))

                            ip_bytes = socket.inet_aton(node.NODE_IP)
                            port_bytes = struct.pack("<H", node.NODE_PORT)
                            payload = ip_bytes + port_bytes

                            conn.sendall(Utils.create_message("handshake", payload))

                            response = conn.recv(1024)
                            if not Utils.check_checksum(response):
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
                                addresses = Utils.parse_addr_payload(payload)
                                # Update known nodes, limiting to 100 addresses
                                if len(addresses) < 100:
                                    for addr in addresses:
                                        if addr not in node.known_nodes:
                                            if Utils.check_node_working(node.NODE_IP, node.NODE_PORT, addr):
                                                node.known_nodes.append(addr)
                                                Utils.save_known_nodes(node.known_nodes)  # Сохраняем изменения

                                else:
                                    conn.close()
                                    if current_node in node.known_nodes:
                                        node.known_nodes.remove(current_node)
                                        Utils.save_known_nodes(node.known_nodes)  # Сохраняем изменения
                                    break

                            try:
                                # Отправка PING
                                conn.sendall(Utils.create_message("ping", b""))

                                # Использование select для установки таймаута
                                ready_to_read, _, _ = select.select([conn], [], [], RESPONSE_TIMEOUT)

                                if ready_to_read:
                                    response = conn.recv(1024)
                                    if not Utils.check_checksum(response):
                                        print("Checksum mismatch")
                                        if current_node in node.known_nodes:
                                            node.known_nodes.remove(current_node)
                                            Utils.save_known_nodes(node.known_nodes)  # Сохраняем изменения
                                        continue

                                    header = response[:16]
                                    command = header[:12].strip(b'\x00').decode('utf-8')

                                    if command == "pong":
                                        print(f"Connection established. {current_node}")
                                        node.client_connections.append(conn)

                            except socket.timeout:
                                print(f"Connection to {current_node} timed out.")
                                conn.close()
                                if current_node in node.known_nodes:
                                    node.known_nodes.remove(current_node)
                                    Utils.save_known_nodes(node.known_nodes)  # Сохраняем изменения

                        except Exception as e:
                            print(f"Failed to connect to {current_node}: {e}")
                            if conn:
                                conn.close()
                            if current_node in node.known_nodes:
                                node.known_nodes.remove(current_node)
                                Utils.save_known_nodes(node.known_nodes)  # Сохраняем изменения

                    time.sleep(CONNECT_INTERVAL)

        def ping_nodes(self) -> None:
            """
            Отправляет ping сообщения всем подключенным узлам и обрабатывает их ответы.
            Если узел не отвечает в течение времени таймаута или возникает ошибка, он удаляется из списка узлов.
            """
            while True:
                with node.lock:
                    current_connections = node.client_connections[:]
                    for conn in current_connections:
                        try:
                            # Отправка PING
                            conn.sendall(Utils.create_message("ping", b""))

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
                                    Utils.remove_node(self, conn)
                            else:
                                print("No response, closing connection.")
                                Utils.remove_node(self, conn)

                        except (socket.error, OSError, BrokenPipeError) as e:
                            print(f"Error with connection: {e}")
                            Utils.remove_node(self, conn)

                time.sleep(PING_INTERVAL)

        def update_nodes_list(self) -> None:
            """
            Получает список узлов и добавляет их в known_nodes, исключая дубликаты.
            Использует таймаут для ожидания ответа и обрабатывает исключения.
            """
            while True:
                with node.lock:
                    current_connections = node.client_connections[:]
                    for conn in current_connections:
                        try:
                            # Запрос списка узлов
                            conn.sendall(Utils.create_message("getaddr", b""))

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
                                    nodes = Utils.parse_addr_payload(payload)

                                    # Обновление known_nodes, исключая дубликаты и ограничивая до 100 узлов
                                    for n in nodes:
                                        if n not in node.known_nodes:
                                            if len(node.known_nodes) < 100:
                                                node.known_nodes.append(n)
                                            else:
                                                break
                                    print(f"Updated known_nodes: {node.known_nodes}")
                            else:
                                print("No response, closing connection.")
                                Utils.remove_node(self, conn)

                        except (socket.error, OSError, BrokenPipeError) as e:
                            print(f"Error with connection: {e}")
                            Utils.remove_node(self, conn)
                time.sleep(UPDATE_INTERVAL)

        def broadcast_difficulty(self) -> None:
            while True:
                with self.node.lock:
                    for node in self.node.known_nodes:
                        try:
                            conn = socket.create_connection(node)
                            conn.settimeout(RESPONSE_TIMEOUT)
                            difficulty_message = f"difficulty:{self.node.difficulty}".encode('utf-8')
                            conn.sendall(Utils.create_message("difficulty", difficulty_message))
                        except Exception as e:
                            print(f"Broadcast difficulty exception: {e}")
                        finally:
                            conn.close()

                time.sleep(UPDATE_INTERVAL)

    def run(self):
        server = self.Server(self)
        client = self.Client(self)

        server_thread = threading.Thread(target=server.start_server)
        connect_thread = threading.Thread(target=client.connect_to_nodes)
        ping_thread = threading.Thread(target=client.ping_nodes)
        update_thread = threading.Thread(target=client.update_nodes_list)
        broadcast_thread = threading.Thread(target=client.broadcast_difficulty)

        server_thread.start()
        connect_thread.start()
        ping_thread.start()
        update_thread.start()
        broadcast_thread.start()

        server_thread.join()
        connect_thread.join()
        ping_thread.join()
        update_thread.join()
        broadcast_thread.join()



if __name__ == "__main__":
    node = Node(NODE_PORT, Utils.load_known_nodes())
    node.run()
