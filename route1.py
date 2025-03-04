from common import generate_keys, sign_message, verify_signature

if __name__ == "__main__":
    client_private_key, client_public_key = generate_keys()

    message = "Hello, Server!"

    signature = sign_message(client_private_key, message)
    print(f"Подпись клиента: {signature}")

    is_valid = verify_signature(client_public_key, message, signature)
    print(f"Статус верификации: {'Успешно' if is_valid else 'Ошибка'}")
