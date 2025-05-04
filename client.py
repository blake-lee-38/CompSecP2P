import socket
import threading
from crypto_utils import *
import threading

def recieve_from_server(sock, key):
    while True:
        try:
            data = sock.recv(4096).decode()
            if not data: break
            print(f"\n Received Encrypted: {data}")
            print(f" Decrypted: {decrypt_message(data, key)}")
        except:
            break

def main():
    password = input("Enter shared password: ")
    salt = b'this_is_our_salt'
    key = derive_key(password, salt)

    def periodic_key_updater():
        global key
        while True:
            time.sleep(300)
            key = derive_key(password)

    threading.Thread(target=periodic_key_updater, daemon=True).start()

    sock = socket.socket()
    sock.connect(('localhost', 5000))

    threading.Thread(target=recieve_from_server, args=(sock, key)).start()

    while True:
        message = input("You: ")
        encrypted_message = encrypt_message(message, key)
        sock.send(encrypted_message.encode())

if __name__ == "__main__":
    main()
