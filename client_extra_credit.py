import socket
import threading
from crypto_utils_extra_credit import *
import rsa
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import random

from crypto_utils_extra_credit import encrypt_message, decrypt_message

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
    
   
    server_public_key = sock.recv(4096)
    server_signature = sock.recv(4096)
    server_public_key_formatted = rsa.PublicKey.load_pkcs1(server_public_key, format='PEM')
    print(f"Received server's public key.")

    try:
        rsa.verify(b"This is server", server_signature, server_public_key_formatted)
        print("Client signature verified.")
    except rsa.VerificationError:
        print("Client signature verification failed.")
        sock.close()
        return
    
    sock.send(pubkey.save_pkcs1(format='PEM'))
    signature = rsa.sign(b"This is client", privkey, 'SHA-256')
    sock.send(signature)
    

    random_number = get_random_bytes(32)  
    print(f" AES key: {random_number}")
    random_number_encrypted = rsa.encrypt(random_number, server_public_key_formatted)
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
