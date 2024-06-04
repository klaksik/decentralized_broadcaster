import asyncio
import os
import json

peers = [
    {"host": "localhost", "port": 10005},
    {"host": "localhost", "port": 10006},
    {"host": "localhost", "port": 10007}
]

async def create_config_files():
    # Создаем конфигурационные файлы для каждого узла
    for i, peer in enumerate(peers):
        # Генерировать имя папки для узла
        node_folder = f"{peer['host']}_{peer['port']}"
        # Проверить существование папки, и если ее нет, создать ее
        if not os.path.exists(node_folder):
            os.makedirs(node_folder)

        config_file = f'{peer["host"]}_{peer["port"]}/node_config.json'
        with open(config_file, 'w') as f:
            json.dump({
                "host": peer["host"],
                "port": peer["port"],
                "peers_file": f'{peer["host"]}_{peer["port"]}/peers.json',
                "blockchain_file": f'{peer["host"]}_{peer["port"]}/blockchain.json',
                "seed_nodes": peers,
                "debug": True
            }, f, indent=4)

async def start_node(peer):
    print(peer)
    process = await asyncio.create_subprocess_exec(
        'python', 'main.py', f'{peer["host"]}_{peer["port"]}/node_config.json'
    )
    await process.communicate()

async def start_nodes():
    # Запуск узлов параллельно
    await asyncio.gather(*[start_node(peer) for peer in peers])

if __name__ == '__main__':
    asyncio.run(create_config_files())
    asyncio.run(start_nodes())
