import threading
from node.node import Node
from network.server import Server
from network.client import Client
from config import NODE_PORT, START_NODES


def main():
    # Инициализация узла
    node = Node(port=NODE_PORT, known_nodes=START_NODES)

    # Запуск клиента
    client = Client(node)
    client_thread = threading.Thread(target=client.start_client, daemon=True)
    client_thread.start()
    print("Client started...")

    # Запуск сервера
    server = Server(node)
    server_thread = threading.Thread(target=server.start_server, daemon=True)
    server_thread.start()
    print("Server started...")

    # Основной поток для выполнения
    try:
        while True:
            pass  # Основной поток продолжает работу
    except KeyboardInterrupt:
        print("Shutting down...")
        # Здесь можно добавить логику для корректного завершения работы, если необходимо


if __name__ == "__main__":
    main()
