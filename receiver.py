import socket
import zlib
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def load_private_key(file_path: str):
    with open(file_path, 'rb') as key_file:
        return serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())


def load_public_key(file_path: str):
    with open(file_path, 'rb') as key_file:
        return serialization.load_pem_public_key(key_file.read(), backend=default_backend())


def receive_packet(port: int = 4040) -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind(('', port))
        server_socket.listen(1)
        print(f"Receiver is listening on port {port}...")

        conn, addr = server_socket.accept()
        print(f"Connected by {addr}")

        data = b""
        while True:
            packet = conn.recv(4096)
            if not packet:
                break
            data += packet

        conn.close()
        return data


def decrypt_payload(encrypted_packet: bytes, receiver_private_key) -> bytes:
    decoded_data = base64.b64decode(encrypted_packet)
    encrypted_key, remaining = decoded_data.split(b'::IV::')
    iv, encrypted_data = remaining.split(b'::DATA::')

    aes_key = receiver_private_key.decrypt(
        encrypted_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
    padding_length = decrypted_padded[-1]
    decompressed_data = decrypted_padded[:-padding_length]

    return zlib.decompress(decompressed_data)


def verify_signature(message: bytes, signature: bytes, sender_public_key) -> bool:
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(message)
    message_hash = digest.finalize()

    try:
        sender_public_key.verify(
            signature,
            message_hash,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


def main():
    print("Waiting for incoming message...")
    received_packet = receive_packet()

    receiver_private_key = load_private_key('keys/receiver_private.pem')
    sender_public_key = load_public_key('keys/sender_public.pem')

    try:
        decrypted_data = decrypt_payload(received_packet, receiver_private_key)
        message, signature = decrypted_data.split(b'%%SIGNATURE%%')

        if verify_signature(message, signature, sender_public_key):
            print("Signature verified successfully. Message is authentic.")
            print("\nMessage content:")
            print(message.decode('utf-8'))

            with open('received_data.txt', 'wb') as file:
                file.write(message)
            print("\nMessage saved to 'received_data.txt'")
        else:
            print("Signature verification failed. Message may have been tampered.")

    except Exception as e:
        print(f"Error processing message: {e}")


if __name__ == "__main__":
    main()
