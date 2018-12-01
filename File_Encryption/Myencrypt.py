# Eleazar Gomez
# Dion Woo
#
# File Encryption Step 1: Myencrypt and Mydecrypt

from os import urandom

from CONSTANTS import *

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


# (C, IV) = Myencrypt(message, key):
#
# In this method, you will generate a 16 Bytes IV, and encrypt
# the message using the key and IV in CBC mode (AES).
# You return an error if the len(key) < 32
# (i.e., the key has to be 32 bytes = 256 bits).

def Myencrypt(message, key):
    # Test if key is 32 bytes (256 bits)
    if (len(key) != KEY_LENGTH_BYTES):
        raise ValueError("Incorrect key length. Must be 256 bits (32 bytes).")

    # Generate random IV
    IV = urandom(IV_LENGTH_BYTES)

    # Create PKCS7 padder
    padder = padding.PKCS7(MESSAGE_LENGTH_BITS).padder()

    # Pass the message to the padder and finalize
    message = padder.update(message)
    message += padder.finalize()

    # Run encryption in CBC mode (AES)
    encryptor = Cipher(algorithms.AES(key), modes.CBC(IV),
                backend = default_backend()).encryptor()
    C = encryptor.update(message) + encryptor.finalize()

    # Return data (C, IV)
    return C, IV


# message = Mydecrypt(ciphertext, key, IV)
#
# Inverse of Myencrypt. Returns the decrypted message.

def Mydecrypt(ciphertext, key, IV):
    # Run decryption in CBC mode (AES)
    decryptor = Cipher(algorithms.AES(key), modes.CBC(IV),
                       backend = default_backend()).decryptor()    
    message = decryptor.update(ciphertext) + decryptor.finalize()

    # Create PKCS7 unpadder
    unpadder = padding.PKCS7(MESSAGE_LENGTH_BITS).unpadder()

    # Pass the message to the unpadder and finalize
    message = unpadder.update(message)
    message = message + unpadder.finalize()

    # Return the message
    return message

# =====================
# TEST
# =====================

if __name__ == "__main__":
    test_key = urandom(KEY_LENGTH_BYTES)

    msg = "test plaintext"

    msg_bytes = str.encode(msg)

    print(msg_bytes)

    x = Myencrypt(msg_bytes, test_key)

    print(Mydecrypt(x[0], test_key, x[1]))
