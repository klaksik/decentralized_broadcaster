import sys
import json
from node import Node
from blockchain import Blockchain
import asyncio
async def start_node(node):
    # Запуск узлов параллельно
    await asyncio.gather(Node.start(node))

def main(config_file):
    with open(config_file, 'r') as f:
        config = json.load(f)

    host = config['host']
    port = config['port']
    peers_file = config['peers_file']
    blockchain_file = config['blockchain_file']
    seed_nodes = config['seed_nodes']
    debug = config['debug']

    blockchain = Blockchain(blockchain_file)
    node = Node(host, port, blockchain, seed_nodes, debug, peers_file)

    asyncio.run(start_node(node))



if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python main.py <config_file>")
        sys.exit(1)

    config_file = sys.argv[1]
    main(config_file)
