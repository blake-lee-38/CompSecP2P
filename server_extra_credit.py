import socket
import threading
from crypto_utils_extra_credit import *
import rsa
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import random

from crypto_utils_extra_credit import encrypt_message, decrypt_message

def handle_client(conn, key):
    while True:
        try:
            data = conn.recv(4096)
            if not data: break
            print(f"\n[Received Encrypted]: {data}")
            print(f"[Decrypted]: {decrypt_message(data, key)}")
        except:
            break

def main():
    
    (pubkey, privkey) = rsa.newkeys(2048)

    sock = socket.socket()
    sock.bind(('0.0.0.0', 4999))
    sock.listen(1)
    print("[Waiting for connection...]")
   
    conn, addr = sock.accept()
    print(f"[Connected to]: {addr}")

    # send public key
    conn.send(pubkey.save_pkcs1(format='PEM'))
    signature = rsa.sign(b"This is server", privkey, 'SHA-256')
    conn.send(signature)

    client_public_key =  conn.recv(4096)
    client_signature = conn.recv(4096)
    client_public_key_formatted = rsa.PublicKey.load_pkcs1(client_public_key, format='PEM')

    try:
        rsa.verify(b"This is client", client_signature, client_public_key_formatted)
        print("Client signature verified.")
    except rsa.VerificationError:
        print("Client signature verification failed.")
        conn.close()
        return
    random_number = get_random_bytes(32)  
    print(f" AES key: {random_number}")
    random_number_encrypted = rsa.encrypt(random_number, client_public_key_formatted)
    conn.send(random_number_encrypted)

    encrypted_number_recieved = conn.recv(4096)
    decrypted_random_number = rsa.decrypt(encrypted_number_recieved, privkey)

    shared_key = (int.from_bytes(decrypted_random_number, byteorder='big') ^ int.from_bytes(random_number, byteorder='big')).to_bytes(32, byteorder='big')
    threading.Thread(target=handle_client, args=(conn, shared_key)).start()

    while True:
        msg = input("You: ")
        enc = encrypt_message(msg, shared_key)
        conn.send(enc)

if __name__ == "__main__":
    main()
