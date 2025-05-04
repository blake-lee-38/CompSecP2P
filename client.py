import socket
import threading
from crypto_utils import *
import threading

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

    def periodic_key_updater():
        global key
        while True:
            time.sleep(300)
            key = derive_key(password)

    threading.Thread(target=periodic_key_updater, daemon=True).start()

    sock = socket.socket()
    sock.connect(('localhost', 5000))

    threading.Thread(target=receive, args=(sock, key)).start()

    while True:
        msg = input("You: ")
        enc = encrypt_message(msg, key)
        sock.send(enc.encode())

if __name__ == "__main__":
    main()
