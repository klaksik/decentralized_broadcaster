import hashlib


def calculate_hash(nonce: str) -> str:
    """Вычисляет SHA-256 хеш для заданного nonce."""
    data = f"blockdata-{nonce}".encode('utf-8')
    print(hashlib.sha256(data).hexdigest())
    return hashlib.sha256(data).hexdigest()


def find_valid_nonce(difficulty: float) -> str:
    """Ищет валидный nonce, удовлетворяющий сложности, заданной в виде float."""
    # Преобразуем float в количество ведущих нулей
    leading_zeros = int(difficulty)
    target_prefix = '0' * leading_zeros
    nonce = 0  # Начальное значение nonce

    while True:
        nonce_str = str(nonce)  # Преобразуем значение nonce в строку
        hash_result = calculate_hash(nonce_str)
        if hash_result.startswith(target_prefix):
            return nonce_str
        nonce += 1


if __name__ == "__main__":
    difficulty = 6.5  # Количество ведущих нулей в хеше

    # Найти валидный nonce
    valid_nonce = find_valid_nonce(difficulty)

    if valid_nonce is not None:
        print(f"Найден валидный nonce: {valid_nonce}")
    else:
        print("Валидный nonce не найден")
