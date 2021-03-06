# Eleazar Gomez
# Dion Woo
#
# File Encryption Step 2: MyencryptMAC and MydecryptMAC

from os import urandom

from CONSTANTS import *

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, hmac

# (C, IV, tag) = MyencryptMAC(message, EncKey, HMACKey)
#
# Modify your File Encryption to include the policy of
# Encrypt-then-MAC for every encryption.

def MyencryptMAC(message, EncKey, HMACKey):
    # Check Key Length
    if (len(EncKey) != KEY_LENGTH_BYTES or len(HMACKey) != KEY_LENGTH_BYTES):
        raise ValueError("Incorrect key(s) length. Must be 256 bits (32 bytes).")

    # Generate random IV
    IV = urandom(IV_LENGTH_BYTES)

    # Pad message (PKCS7)
    padder = padding.PKCS7(MESSAGE_LENGTH_BITS).padder()	
    message = padder.update(message)
    message += padder.finalize()

    # Encrypt
    encryptor = Cipher(algorithms.AES(EncKey), modes.CBC(IV),
                backend = default_backend()).encryptor()
    C = encryptor.update(message) + encryptor.finalize()

    # MAC (SHA256)
    t = hmac.HMAC(HMACKey, hashes.SHA256(), backend = default_backend())
    t.update(C)
    tag = t.finalize()
	
    return C, IV, tag

# message = MydecryptMAC(C, IV, tag, EncKey, HMACKey)
#
# Inverse of MyencryptMAC. Returns the decrypted message.

def MydecryptMAC(C, IV, tag, EncKey, HMACKey):
    # Verify tag
    verificationTag = hmac.HMAC(HMACKey, hashes.SHA256(),
                               backend = default_backend())
    verificationTag.update(C)
    verificationTag.verify(tag)

    # Decrypt
    decryptor = Cipher(algorithms.AES(EncKey), modes.CBC(IV),
                       backend = default_backend()).decryptor()
    message = decryptor.update(C) + decryptor.finalize()

    # Unpad
    unpadder = padding.PKCS7(MESSAGE_LENGTH_BITS).unpadder()
    message = unpadder.update(message)
    message = message + unpadder.finalize()

    # Return the message
    return message

# =====================
# TEST
# =====================

if __name__ == "__main__":
    test_EncKey = urandom(KEY_LENGTH_BYTES)
    test_HMACKey = urandom(KEY_LENGTH_BYTES)

    msg = "test plaintext"

    msg_bytes = str.encode(msg)

    print(msg_bytes)

    x = MyencryptMAC(msg_bytes, test_EncKey, test_HMACKey)

    print(MydecryptMAC(x[0],x[1], x[2], test_EncKey, test_HMACKey))
