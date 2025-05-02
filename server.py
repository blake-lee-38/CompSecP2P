import socket
import threading
from crypto_utils import *

def handle_client(conn, key):
    while True:
        try:
            data = conn.recv(4096).decode()
            if not data: break
            print(f"\n[Received Encrypted]: {data}")
            print(f"[Decrypted]: {decrypt_message(data, key)}")
        except:
            break

def main():
    password = input("Enter shared password: ")
    salt = b'secure_salt_1234'
    key = derive_key(password, salt)

    sock = socket.socket()
    sock.bind(('0.0.0.0', 5000))
    sock.listen(1)
    print("[Waiting for connection...]")
    conn, addr = sock.accept()
    print(f"[Connected to]: {addr}")

    threading.Thread(target=handle_client, args=(conn, key)).start()

    while True:
        msg = input("You: ")
        enc = encrypt_message(msg, key)
        conn.send(enc.encode())

if __name__ == "__main__":
    main()
