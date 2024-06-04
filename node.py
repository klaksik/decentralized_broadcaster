import asyncio
import socket
import json
import random
import logging
import os
from blockchain import Blockchain
from block import Block
import aiofiles

class Node:
    def __init__(self, host, port, blockchain, seed_nodes, debug, peers_file):
        # Определение переменных класса и инициализация
        self.max_min_peers = 6
        self.host = host
        self.port = port
        self.blockchain = blockchain
        self.seed_nodes = seed_nodes
        self.debug = debug
        self.peers_file = peers_file
        self.connected_peers = []
        self.logger = logging.getLogger(__name__)
        self.peers = []


    async def save_blockchain(self):
        # Сохранение блокчейна в файл
        blockchain_file_path = os.path.join(self.blockchain_file)
        async with aiofiles.open(blockchain_file_path, 'w') as f:
            await f.write(json.dumps([block.__dict__ for block in self.blockchain.chain], indent=4))

    async def load_blockchain(self):
        # Загрузка блокчейна из файла
        blockchain_path = os.path.join(self.node_folder, f"{self.host}_{self.port}/node_config.json")
        if os.path.exists(blockchain_path):
            async with aiofiles.open(blockchain_path, "r") as f:
                self.blockchain = json.loads(await f.read())

    async def save_peers(self):
        # Сохранение списка узлов в файл
        peers_list = [{'host': peer['host'], 'port': peer['port']} for peer in self.peers]
        peers_file_path = os.path.join(self.peers_file)
        async with aiofiles.open(peers_file_path, 'w') as f:
            await f.write(json.dumps(peers_list, indent=4))

    async def load_peers_from_file(self):
        # Загрузка списка узлов из файла
        if os.path.exists(self.peers_file):
            async with aiofiles.open(self.peers_file, "r") as f:
                content = await f.read()
                if content.strip():  # Проверка на непустое содержимое
                    self.peers = json.loads(content)
                else:
                    self.peers = []
                if self.debug:
                    print(f"Loaded peers from file: {self.peers}")
        else:
            self.peers = []
            if self.debug:
                print("Peers file does not exist, starting with an empty list.")

    async def update_peers_periodically(self):
        # Периодическое обновление списка узлов
        await self.load_peers_from_file()  # Загрузка списка узлов из файла
        while True:
            for connected_peer in self.connected_peers:
                # Запрос списка узлов у конкретного узла
                try:
                    reader, writer = connected_peer['reader'], connected_peer['writer']
                    writer.write(b"GET_PEERS")
                    await writer.drain()

                    data = await reader.read(1024)
                    if data:
                        print(data.decode())
                        peer_list = json.loads(data.decode())
                        await self.update_peer_list(peer_list)
                    writer.close()
                    await writer.wait_closed()
                except Exception as e:
                    if self.debug:
                        print(f"Failed to sent to peer {connected_peer['host']}:{connected_peer['port']} - {e}")
                    await self.remove_connected_peer(connected_peer)
            await asyncio.sleep(5)

    async def remove_peer(self, peer):
        # Удаление узла из списка подключенных узлов
        if peer in self.peers:
            self.peers.remove(peer)
            if self.debug:
                print(f"Removed peer {peer} from the list of connected peers.")
    async def remove_connected_peer(self, peer):
        # Удаление узла из списка подключенных узлов
        if peer in self.peers:
            self.peers.remove(peer)
            if self.debug:
                print(f"Removed peer {peer} from the list of connected peers.")
    async def update_peer_list(self, new_peers):
        # Обновление списка подключенных узлов
        for peer in new_peers:
            if peer not in self.peers:
                self.peers.append(peer)
                await save_peers()
        for peer in self.peers:
            if not await self.is_peer_available(peer):
                await self.remove_peer(peer)

    async def is_peer_available(self, peer):
        # Проверка доступности узла
        try:
            reader, writer = await asyncio.open_connection(peer['host'], peer['port'])
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False

    async def is_port_available(self, port):
        # Проверка доступности порта
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(('localhost', port))
            except OSError:
                return False
        return True

    async def start(self):
        # Запуск узла
        await asyncio.gather(
            self.connect_to_peers(),
            #self.update_peers_periodically(),
            self.run_server()
        )

    async def connect_to_peers(self):
        # Подключение к другим узлам

        #проверка на количество пиров, если их больше чем 0 то брать все из них, если их меньше чем 6 то добирать из сид нод
        await self.connect_to_seed_nodes()
        await self.connect_to_additional_peers()

        await self.save_peers()

    async def connect_to_additional_peers(self):
        # Подключение к дополнительным узлам из файла peers
        peers = []
        if os.path.exists(self.peers_file):
            async with aiofiles.open(self.peers_file, "r") as f:
                peers = json.loads(await f.read())
        for peer in peers:
            print(len(self.connected_peers))
            if len(self.connected_peers) >= self.max_min_peers:
                break
            if peer not in self.connected_peers:
                await self.connect_to_peer(peer['host'], peer['port'])

    async def run_server(self):
        # Запуск сервера
        while True:
            if await self.is_port_available(self.port):
                try:
                    server = await asyncio.start_server(self.handle_client, self.host, self.port)
                    print(f"Node started on {self.host}:{self.port}")

                    async with server:
                        await server.serve_forever()
                except OSError as e:
                    if e.errno == 10048:
                        print(f"Port {self.port} is already in use. Trying again in 5 seconds...")
                        await asyncio.sleep(5)
                    else:
                        raise
            else:
                print(f"Port {self.port} is already in use. Trying again in 5 seconds...")
                await asyncio.sleep(5)
    async def handle_client(self, reader, writer):
        # Обработка запросов от клиентов
        while True:
            data = await reader.read(1024)
            if not data:
                break
            await self.process_data(data.decode(), writer)
            if self.debug:
                print(f"Received command: {data.decode()}")
    async def process_data(self, data: str, writer):
        # Обработка входящих данных

        if data == 'GET_PEERS':
            response_data = ""
            for peer in self.connected_peers:
                response_data += f"{peer['host']}:{peer['port']}\n"
            writer.write(response_data.encode())
            await writer.drain()

        elif data == 'request_latest_block':
            pass

        else:
            print(f"Unknown message type: {message_type}")
    async def connect_to_peer(self, peer_host: str, peer_port: int):
        # Подключение к конкретному узлу
        reader, writer = await asyncio.open_connection(peer_host, peer_port)
        self.connected_peers.append({'host': peer_host, 'port': peer_port, 'reader': reader, 'writer': writer})

        print(f"Connected to peer {peer_host}:{peer_port}")

    async def connect_to_seed_nodes(self):
        print("connect_to_seed_nodes")
        # Подключение к сид-узлам
        connected_peers = 0
        for seed in self.seed_nodes:
            try:
                if len(self.connected_peers) < self.max_min_peers:
                    await self.connect_to_peer(seed['host'], seed['port'])
                    connected_peers += 1
                    print(f"node {self.host}:{self.port} connected to {seed['host']}:{seed['port']}")

                    if connected_peers >= self.max_min_peers:
                        break
            except Exception as e:
                print(f"Failed to connect to seed node {seed['host']}:{seed['port']} - {e}")




