import os
import json

from CONSTANTS import *
from MyencryptMAC import *

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, hmac


def MyfileEncryptMAC(filepath):
    # Read file
    splitFilePath = os.path.splitext(filepath)
    ext = splitFilePath[1]
    
    if(ext == '.txt'):
        file = open(filepath, 'r')
        content = file.read()
        encodedContent = content.encode()
        encodedFilepath = '..\\..\\encodedFile.txt'
    else:
        file = open(filepath, 'rb')
        encodedContent = file.read()
        encodedFilepath = '..\\..\\encodedFile.jpeg'
        
    file.close()

    # Generate keys
    EncKey = os.urandom(KEY_LENGTH_BYTES)
    HMACKey = os.urandom(KEY_LENGTH_BYTES)

    # Encrypt
    C, IV, tag = MyencryptMAC(encodedContent, EncKey, HMACKey)
    
    file = open(encodedFilepath, 'wb')
    file.write(C)
    file.close()
    
    return C, IV, EncKey, HMACKey, tag, ext, encodedFilepath

def MyfileDecryptMAC(IV, EncKey, HMACKey, tag, ext, filepath):
    # Read file
    file = open(filepath, 'rb')
    content = file.read()
    file.close()

    # Verify tag
    verificationTag = hmac.HMAC(HMACKey, hashes.SHA256(),
                               backend = default_backend())
    verificationTag.update(content)
    verificationTag.verify(tag)

    # Decrypt
    message = MydecryptMAC(content, IV, tag, EncKey, HMACKey)

    # Output
    if(ext == '.txt'):
        message = message.decode()
        file = open('..\\..\\decodedFile.txt', 'w')
        file.write(message)
        file.close()
    else:
        file = open('..\\..\\decodedFile.jpeg', 'wb')
        file.write(message)
        file.close()
            
    return message

# =====================
# TEST
# =====================

if __name__ == "__main__":
    print("Which file do you wish to test, 1. TXT_test.txt or 2. JPEG_test.jpeg? ")
    choice = 0

    while (choice != 1 and choice != 2):
        try:
            choice = int(input())
            if (choice != 1 and choice != 2):
                print("Invalide choice")
            else:
                break
        except:
            print("Invalid data")

    if (choice == 1):
        x = MyfileEncryptMAC("..\\Test_Files\\TXT_test.txt")
        message = MyfileDecryptMAC(x[1], x[2], x[3], x[4], x[5], x[6])
        print(message)
    else:
        x = MyfileEncryptMAC("..\\Test_Files\\JPEG_test.jpeg")
        message = MyfileDecryptMAC(x[1], x[2], x[3], x[4], x[5], x[6])
