def calculate_difficulty_target(blockchain_weight, block_weight, base_difficulty_target: int) -> int:
    # Налаштуйте коефіцієнти для регулювання складності
    weight_factor = 0.01  # Вплив ваги блокчейна на складність
    block_factor = 0.05  # Вплив ваги блоку на складність

    # Розрахунок нової складності
    new_difficulty_target = base_difficulty_target // (int(blockchain_weight * weight_factor) + int(block_weight * block_factor))
    print(new_difficulty_target)
    # Забезпечення мінімального значення для difficulty_target
    min_difficulty_target = 1
    new_difficulty_target = max(min_difficulty_target, new_difficulty_target)

    return int(new_difficulty_target)


# Приклад використання
blockchain_weight = 300000  # Вага блокчейна
block_weight = 3000  # Вага блоку
base_difficulty_target = 2 ** 256 // 10000  # Базовий рівень difficulty_target

difficulty_target = calculate_difficulty_target(blockchain_weight, block_weight, base_difficulty_target)
print(difficulty_target)

import hashlib


def mine_nonce(difficulty_target):
    nonce = 0
    while True:
        # Генерация данных и nonce
        data = f"some_data{nonce}".encode('utf-8')

        # Вычисление хеша
        hash_result = hashlib.sha256(data).hexdigest()

        # Преобразование хеша в целое число
        hash_value = int(hash_result, 16)

        # Проверка, удовлетворяет ли хеш целевому значению
        if hash_value <= difficulty_target:
            return nonce, hash_result

        nonce += 1


nonce, hash_result = mine_nonce(difficulty_target)
print(f"Found nonce: {nonce}")
print(f"Hash: {hash_result}")
