import socket
import threading
from crypto_utils import *
import rsa
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import random

def receive(sock, key):
    while True:
        try:
            data = sock.recv(4096)
            if not data: break
            print(f"\n[Received Encrypted]: {data}")
            print(f"[Decrypted]: {decrypt_message(data, key)}")
        except:
            break

def main():
    
    (pubkey, privkey) = rsa.newkeys(2048)
    

    sock = socket.socket()
    sock.connect(('localhost', 4999))
    
   
    server_pubkey = sock.recv(4096)
    server_pubkey_formatted = rsa.PublicKey.load_pkcs1(server_pubkey, format='PEM')
    print(f"Received server's public key.")

    
    sock.send(pubkey.save_pkcs1(format='PEM'))

    random_number = get_random_bytes(32)  
    print(f" AES key: {random_number}")
    random_number_encrypted = rsa.encrypt(random_number, server_pubkey_formatted)
    sock.send(random_number_encrypted)

    encrypted_number_recieved = sock.recv(4096)
    decrypted_random_number = rsa.decrypt(encrypted_number_recieved, privkey)

    shared_key = (int.from_bytes(decrypted_random_number, byteorder='big') ^ int.from_bytes(random_number, byteorder='big')).to_bytes(32, byteorder='big')
    threading.Thread(target=receive, args=(sock, shared_key)).start()

    while True:
        msg = input("You: ")
        enc = encrypt_message(msg, shared_key)
        sock.send(enc)

if __name__ == "__main__":
    main()
