import threading
from node import Node
from server import Server
from client import Client
from config import NODE_PORT, START_NODES


def main():
    # Инициализация узла
    node = Node(port=NODE_PORT, known_nodes=START_NODES)

    # Запуск сервера
    server = Server(node)
    server_thread = threading.Thread(target=server.start_server, daemon=True)
    server_thread.start()
    print("Server started...")

    # Запуск клиента
    client = Client(node)
    client_thread = threading.Thread(target=client.start_client, daemon=True)
    client_thread.start()
    print("Client started...")

    # Основной поток для выполнения
    try:
        while True:
            pass  # Основной поток продолжает работу
    except KeyboardInterrupt:
        print("Shutting down...")
        # Здесь можно добавить логику для корректного завершения работы, если необходимо


if __name__ == "__main__":
    main()
