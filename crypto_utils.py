from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import base64

def derive_key(password, salt, key_len=32):
    return PBKDF2(password, salt, dkLen=key_len, count=100000)

# Encrypts using AES CBC mode and the shared key from the password and salt
def encrypt_message(message, key):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = message.encode() + b"\0" * (AES.block_size - len(message.encode()) % AES.block_size)
    ciphertext = cipher.encrypt(padded)
    return base64.b64encode(iv + ciphertext).decode()

def decrypt_message(ciphertext_b64, key):
    data = base64.b64decode(ciphertext_b64)
    iv = data[:16]
    ciphertext = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = cipher.decrypt(ciphertext)
    return padded.rstrip(b"\0").decode()
