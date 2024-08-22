
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
    "data": "Welcome to Decentralized Broadcaster",
    "nonce": 0,
    "path": "",
    "file_name": "",
    "pubkey": "",
    "hash_pubkey": "",
    "data_sign": "",
    "hash": "0"
}

BLOCKCHAIN_DIR = "blockchain"
DIFFICULTY_ADJUSTMENT_INTERVAL = 600  # Интервал для корректировки сложности в секундах
BLOCK_GENERATION_TARGET = 10  # Целевое время генерации блока в секундах
START_NODES = []
BASE_DIFFICULTY = 2 ** 256 // 10000  # Базовый уровень difficulty_target