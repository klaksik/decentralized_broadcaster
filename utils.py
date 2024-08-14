import hashlib
import json
import os
import socket
import struct
import random
import time
from typing import List, Tuple


class Utils:
    @staticmethod
    def create_message(command: str, payload: bytes) -> bytes:
        """Створює повідомлення з заголовком та пейлоадом."""
        # Заголовок повідомлення
        header = command.encode('utf-8') + b'\x00' * (12 - len(command))  # Команда і заповнювач до 12 байт
        length = len(payload)  # Довжина пейлоаду
        header += struct.pack("<I", length)  # Довжина пейлоаду у заголовку (4 байти, малий порядок байтів)

        # Контрольна сума (перші 4 байти від хешу заголовка + пейлоаду)
        checksum = struct.pack("<I", sum(header + payload) % 2 ** 32)

        # Збираємо повідомлення
        message = header + payload + checksum

        return message

    @staticmethod
    def check_checksum(data: bytes) -> bool:
        """Перевіряє контрольну суму."""
        header = data[:16]
        command = header[:12].strip(b'\x00').decode('utf-8')  # Витягуємо команду з заголовка
        payload_length = struct.unpack("<I", header[12:16])[0]  # Довжина пейлоаду

        if len(data) < 16 + payload_length:
            return False  # Якщо дані менше, ніж очікувалось, контрольна сума невірна

        payload = data[16:16 + payload_length]  # Витягуємо пейлоад
        checksum_received = data[16 + payload_length:20 + payload_length]  # Отримана контрольна сума

        checksum_calculated = struct.pack("<I", sum(header + payload) % 2 ** 32)  # Обчислюємо контрольну суму
        return checksum_received == checksum_calculated  # Порівнюємо контрольні суми

    @staticmethod
    def parse_addr_payload(payload: bytes) -> List[Tuple[str, int]]:
        """Парсить пейлоад Addr та повертає список адресів."""
        addresses = []
        num_addresses = struct.unpack("<B", payload[0:1])[0]  # Кількість адресів
        index = 1

        for _ in range(num_addresses):
            ip_parts = struct.unpack("<BBBB", payload[index:index + 4])  # Розпаковуємо IP адрес
            ip = ".".join(map(str, ip_parts))  # Формуємо рядок IP адреси
            port = struct.unpack(">H", payload[index + 4:index + 6])[0]  # Розпаковуємо порт
            addresses.append((ip, port))  # Додаємо адресу до списку
            index += 6  # IP (4 байти) + порт (2 байти)
            # Пропускаємо 4 байти для часу
            index += 4

        return addresses

    @staticmethod
    def create_addr_payload(addresses: List[Tuple[str, int]]) -> bytes:
        """Створює пейлоад Addr, з обмеженням до 100 адресів."""
        if len(addresses) > 100:
            addresses = random.sample(addresses, 100)  # Вибираємо випадкові 100 адрес

        payload = b""
        payload += struct.pack("<B", len(addresses))  # Кількість адресів

        for addr, port in addresses:
            ip_parts = list(map(int, addr.split('.')))
            payload += struct.pack("<BBBB", *ip_parts)  # IP адрес

            payload += struct.pack(">H", port)  # Порт (2 байти)

            payload += struct.pack("<I", int(time.time()))  # Час у секундах з моменту епохи Unix

        return payload

    @staticmethod
    def save_known_nodes(known_nodes) -> None:
        """
        Сохраняет known_nodes в файл data.json в формате JSON.
        """
        with open('data.json', 'w') as f:
            json.dump(known_nodes, f)

    @staticmethod
    def load_known_nodes() -> List[Tuple[str, int]]:
        """
        Загружает known_nodes из файла data.json, если файл существует.
        """
        if os.path.exists('data.json'):
            with open('data.json', 'r') as f:
                return json.load(f)
        return []

    @staticmethod
    def calculate_hash(block):
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    @staticmethod
    def remove_node(self, conn: socket.socket) -> None:
        """
        Удаляет узел из списков client_connections и known_nodes и закрывает соединение.
        """
        node = (conn.getpeername()[0], conn.getpeername()[1])
        if node in self.known_nodes:
            self.known_nodes.remove(node)
            Utils.save_known_nodes(self)  # Сохраняем изменения
        if conn in self.client_connections:
            self.client_connections.remove(conn)
        conn.close()

    @staticmethod
    def check_node_working(node_ip, node_port, check_node: Tuple[str, int]) -> bool:
        """
        Проверяет, работает ли узел, отправляя ему PING и ожидая PONG.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
                conn.settimeout(5)
                conn.connect(check_node)

                ip_bytes = socket.inet_aton(node_ip)
                port_bytes = struct.pack("<H", node_port)
                payload = ip_bytes + port_bytes

                conn.sendall(Utils.create_message("handshake", payload))

                response = conn.recv(1024)
                if not Utils.check_checksum(response):
                    print("Checksum mismatch")
                    conn.close()
                    return False

                header = response[:16]
                command = header[:12].strip(b'\x00').decode('utf-8')
                payload_length = struct.unpack("<I", header[12:16])[0]

                if len(response) < 16 + payload_length:
                    return False

                if command == "addr":
                    return True

        except (socket.timeout, socket.error) as e:
            print(f"Failed to connect to {check_node}: {e}")
        return False

    @staticmethod
    def create_handshake_message(ip: str, port: int) -> bytes:
        ip_bytes = socket.inet_aton(ip)
        port_bytes = struct.pack("<H", port)
        return b"handshake" + struct.pack("<I", len(ip_bytes + port_bytes)) + ip_bytes + port_bytes

