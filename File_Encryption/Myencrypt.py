import os

from CONSTANTS import *

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

#from pathlib import Path

def Myencrypt(message, key):
    if (len(key) * BITS_PER_BYTE != KEY_LENGTH_BITS):
        raise ValueError("Incorrect key length. Must be 256 bits.")

    IV = os.urandom(IV_LENGTH_BYTES)
    padder = padding.PKCS7(MESSAGE_LENGTH_BITS).padder()
	
    message = padder.update(message)
    message += padder.finalize()
	
    encryptor = Cipher(algorithms.AES(key), modes.CBC(IV),
                backend = default_backend()).encryptor()
    C = encryptor.update(message) + encryptor.finalize()
	
    return (C, IV)

def Mydecrypt(ciphertext, key, IV):
    decryptor = Cipher(algorithms.AES(key), modes.CBC(IV),
                       backend = default_backend()).decryptor()
    
    message = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(MESSAGE_LENGTH_BITS).unpadder()
    message = unpadder.update(message)
    message = message + unpadder.finalize()
    
    return message

# =====================
# TEST
# =====================

test_key = os.urandom(int(KEY_LENGTH_BITS / BITS_PER_BYTE))

msg = "test plaintext"

msg_bytes = str.encode(msg)

print(msg_bytes)

x = Myencrypt(msg_bytes, test_key)

print(Mydecrypt(x[0], test_key, x[1]))
