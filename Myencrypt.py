import os
#import sys
#import json
#import base64

from CONSTANTS import *

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def Myencrypt(plaintext, key):
    if (len(key) * BITS_PER_BYTE != KEY_LENGTH_BITS):
        raise ValueError("Incorrect key length. Must be 256 bits.")
    
    IV = os.urandom(IV_LENGTH_BYTES)

    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv),
                       backend = default_backend()).encryptor()

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return (ciphertext, IV)
    

def Mydecrypt(ciphertext, IV, key):
  decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag),
                     backend=default_backend()).decryptor()

  return decryptor.update(ciphertext) + decryptor.finalize()

# =====================
# TEST
# =====================

test_key = os.urandom(KEY_LENGTH_BITS / BITS_PER_BYTE)

print(Myencrypt("test plaintext", test_key))


##def MyfileEncrypt(filepath):
##  key_length = 32
##  key = os.urandom(key_length)
##  
##  file_name = os.path.splitext(filepath)[0]
##  file_extension = os.path.splitext(filepath)[1]
##
##  with open(filepath, "rb") as binary_file:
##    # Read the whole file at once
##    data = binary_file.read()
##    iv, ciphertext, tag = Myencrypt(
##      data,
##      key
##    )
##    
##    return (ciphertext, tag, iv, key, file_extension)
##
##def MyfileDecrypt(filepath, key):
##  file_name = os.path.splitext(filepath)[0]
##  
##  with open(filepath, 'r') as f:
##    data = json.load(f)
##    
##    iv = base64.b64decode(data['iv'])
##    ciphertext = base64.b64decode(data['ciphertext_base64'])
##    tag = base64.b64decode(data['tag'])
##  
##    plaintext = Mydecrypt(ciphertext, tag, iv, key)
##    
##    output_filename = file_name + data['file_extension']
##    
##    f = open(output_filename, 'wb')
##    f.write(plaintext)
##    f.close()
##    
##    return output_filename
