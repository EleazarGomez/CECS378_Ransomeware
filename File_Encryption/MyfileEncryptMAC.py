import os
import json
import binascii

from CONSTANTS import *
from MyencryptMAC import *

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, hmac


def MyfileEncryptMAC(filepath):
    # Read file
    splitFilePath = os.path.splitext(filepath)
    split = splitFilePath[0].split("\\")
    filename = split[len(split) - 1]
    ext = splitFilePath[1]
    
    if(ext == '.txt'):
        file = open(filepath, 'r')
        content = file.read()
        encodedContent = content.encode()
    else:
        file = open(filepath, 'rb')
        encodedContent = file.read()
        
    file.close()

    # Generate keys
    EncKey = os.urandom(KEY_LENGTH_BYTES)
    HMACKey = os.urandom(KEY_LENGTH_BYTES)

    # Encrypt
    C, IV, tag = MyencryptMAC(encodedContent, EncKey, HMACKey)
    
    return filename, C, IV, tag, EncKey, HMACKey, ext

def MyfileDecryptMAC(filename, C, IV, tag, EncKey, HMACKey, ext):
    # Verify tag
    verificationTag = hmac.HMAC(HMACKey, hashes.SHA256(),
                               backend = default_backend())
    verificationTag.update(C)
    verificationTag.verify(tag)

    # Decrypt
    message = MydecryptMAC(C, IV, tag, EncKey, HMACKey)

    # Output
    if(ext == '.txt'):
        message = message.decode()
        file = open('..\\..\\' + filename + 'DEC.txt', 'w')
        file.write(message)
        file.close()
    else:
        file = open('..\\..\\' + filename + 'DEC' + ext, 'wb')
        file.write(message)
        file.close()
            
    return message

# =====================
# TEST
# =====================

if __name__ == "__main__":
    print("Which file do you wish to test, 1. TXT_test.txt" \
          ", 2. JPEG_test.jpeg or 3. JPG_test.jpg? ")
    choice = 0

    while (choice != 1 and choice != 2 and choice != 3):
        try:
            choice = int(input())
            if (choice != 1 and choice != 2 and choice != 3):
                print("Invalide choice")
            else:
                break
        except:
            print("Invalid data")

    if (choice == 1):
        x, C, IV, tag, EncKey, HMACKey, ext = MyfileEncryptMAC("..\\Test_Files\\TXT_test.txt")
        message = MyfileDecryptMAC(x, C, IV, tag, EncKey, HMACKey, ext)
        print(message)
    elif (choice == 2):
        x, C, IV, tag, EncKey, HMACKey, ext = MyfileEncryptMAC("..\\Test_Files\\JPEG_test.jpeg")
        message = MyfileDecryptMAC(x, C, IV, tag, EncKey, HMACKey, ext)
    else:
        x, C, IV, tag, EncKey, HMACKey, ext = MyfileEncryptMAC("..\\Test_Files\\JPG_test.jpg")
        message = MyfileDecryptMAC(x, C, IV, tag, EncKey, HMACKey, ext)
