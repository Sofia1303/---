from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import requests
import base64

client_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
client_public_key = client_private_key.public_key()


def sign_message(private_key, message):
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()


def scenario_1():
    client_id = "client_1"
    public_key_pem = client_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    response = requests.post(
        "http://127.0.0.1:5000/register_client_key",
        json={"client_id": client_id, "public_key": public_key_pem}
    )
    print(f"Регистрация ключа клиента: {response.json()}")

    message = "Hello, Server!"

    signature = sign_message(client_private_key, message)
    print(f"Подпись клиента: {signature}")

    response = requests.post(
        "http://127.0.0.1:5000/verify",
        json={"client_id": client_id, "message": message, "signature": signature}
    )
    print(f"Статус верификации: {response.json()}")


def scenario_2():
    response = requests.get("http://127.0.0.1:5000/public_key")
    server_public_key_pem = response.json()["public_key"]
    server_public_key = serialization.load_pem_public_key(
        server_public_key_pem.encode())

    response = requests.get("http://127.0.0.1:5000/generate_signed_message")
    data = response.json()
    random_message = data["message"]
    server_signature = data["signature"]

    print(f"Случайное сообщение от сервера: {random_message}")
    print(f"Подпись сервера: {server_signature}")

    from cryptography.exceptions import InvalidSignature
    try:
        server_public_key.verify(
            base64.b64decode(server_signature),
            random_message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print(f"Статус верификации: Успешно")
    except InvalidSignature:
        print(f"Статус верификации: Ошибка")


if __name__ == "__main__":
    print("=== Сценарий 1 ===")
    scenario_1()

    print("\n=== Сценарий 2 ===")
    scenario_2()
