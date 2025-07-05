import base64
import socket
import zlib
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes



def load_private_key(file_path: str):
    with open(file_path, 'rb') as key_file:
        return serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())


def load_public_key(file_path: str):
    with open(file_path, 'rb') as key_file:
        return serialization.load_pem_public_key(key_file.read(), backend=default_backend())


def sign_message(message: bytes, private_key) -> bytes:
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(message)
    message_hash = digest.finalize()

    signature = private_key.sign(
        message_hash,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return signature


def encrypt_payload(payload: bytes, receiver_public_key) -> bytes:
    compressed_payload = zlib.compress(payload)
    
    iv = os.urandom(16)
    aes_key = os.urandom(32)

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padding_length = 16 - (len(compressed_payload) % 16)
    padded_payload = compressed_payload + bytes([padding_length]) * padding_length

    encrypted_payload = encryptor.update(padded_payload) + encryptor.finalize()

    encrypted_key = receiver_public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    packet = encrypted_key + b'::IV::' + iv + b'::DATA::' + encrypted_payload
    return base64.b64encode(packet)


def send_packet(ip: str, port: int, packet: bytes):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((ip, port))
        sock.sendall(packet)


def main():
    receiver_ip = input("Receiver IP address: ")
    message_input = input("Enter your message: ")
    message = message_input.encode()

    sender_private_key = load_private_key('keys/sender_private.pem')
    receiver_public_key = load_public_key('keys/receiver_public.pem')

    signature = sign_message(message, sender_private_key)
    combined_payload = message + b'%%SIGNATURE%%' + signature

    encrypted_packet = encrypt_payload(combined_payload, receiver_public_key)

    try:
        send_packet(receiver_ip, 4040, encrypted_packet)
        print("Message sent successfully.")
    except Exception as e:
        print(f"Error while sending message: {e}")


if __name__ == "__main__":
    main()
