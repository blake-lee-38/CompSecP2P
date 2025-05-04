import socket
import threading
from crypto_utils import *

def recieve_from_client(conn, key):
    while True:
        try:
            data = conn.recv(4096).decode()
            if not data: break
            print(f"\n Received Encrypted: {data}")
            print(f"Decrypted: {decrypt_message(data, key)}")
        except:
            break

def main():
    password = input("Enter shared password: ")
    salt = b'this_is_our_salt'
    key = derive_key(password, salt)

    sock = socket.socket()
    sock.bind(('0.0.0.0', 5000))
    sock.listen(1)
    print("Waiting for client")
    conn, addr = sock.accept()
    print(f"Connected to: {addr}")

    threading.Thread(target=recieve_from_client, args=(conn, key)).start()

    while True:
        message = input("You: ")
        encrypted_message = encrypt_message(message, key)
        conn.send(encrypted_message.encode())

if __name__ == "__main__":
    main()
