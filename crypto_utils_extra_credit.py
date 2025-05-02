from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2



def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_message = message.encode() + (b'\0' * (AES.block_size - len(message.encode()) % AES.block_size))
    ciphertext = cipher.encrypt(padded_message)
    return ciphertext

def decrypt_message(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_message = cipher.decrypt(ciphertext)
    return decrypted_message.rstrip(b'\0').decode()
