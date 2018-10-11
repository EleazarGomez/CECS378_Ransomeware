import os

from CONSTANTS import *

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

def Myencrypt(message, key):
    if (len(key) != KEY_LENGTH_BYTES):
        raise ValueError("Incorrect key length. Must be 256 bits (32 bytes).")

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

if __name__ == "__main__":
    test_key = os.urandom(KEY_LENGTH_BYTES)

    msg = "test plaintext"

    msg_bytes = str.encode(msg)

    print(msg_bytes)

    x = Myencrypt(msg_bytes, test_key)

    print(Mydecrypt(x[0], test_key, x[1]))
