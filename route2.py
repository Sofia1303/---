from cryptography.hazmat.primitives import serialization
from common import generate_keys, sign_message, verify_signature


def generate_random_message():
    import random
    import string
    return ''.join(random.choices(string.ascii_letters + string.digits, k=16))


if __name__ == "__main__":
    server_private_key, server_public_key = generate_keys()

    random_message = generate_random_message()
    print(f"Случайное сообщение от сервера: {random_message}")

    server_signature = sign_message(server_private_key, random_message)
    print(f"Подпись сервера: {server_signature}")

    serialized_public_key = server_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print(f"Публичный ключ сервера:\n{serialized_public_key.decode()}")

    deserialized_public_key = serialization.load_pem_public_key(
        serialized_public_key)
    is_valid = verify_signature(
        deserialized_public_key, random_message, server_signature)
    print(f"Статус верификации: {'Успешно' if is_valid else 'Ошибка'}")
