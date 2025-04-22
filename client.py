import socket
import threading
from crypto_utils import *

def receive(sock, key):
    while True:
        try:
            data = sock.recv(4096).decode()
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
    sock.connect(('localhost', 5000))

    threading.Thread(target=receive, args=(sock, key)).start()

    while True:
        msg = input("You: ")
        enc = encrypt_message(msg, key)
        sock.send(enc.encode())

if __name__ == "__main__":
    main()
