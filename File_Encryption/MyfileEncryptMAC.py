import os

from CONSTANTS import *
from Myencrypt import *

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, serialization, hashes, hmac

def MyfileEncryptMAC(filepath):
    splitFilePath = os.path.splitext(filepath)
    ext = splitFilePath[1]
    
    if(ext == '.txt'):
        file = open(filepath, 'r')
        content = file.read()
        encodedContent = content.encode()
        encodedFilepath = '..\\..\\encodedFileMAC.txt'
    else:
        file = open(filepath, 'rb')
        encodedContent = file.read()
        encodedFilepath = '..\\..\\encodedFileMAC.jpg'
        
    file.close()

    EncKey = os.urandom(32)
    HMACKey = os.urandom(32)

    C, IV, tag = MyencryptMAC(encodedContent, EncKey, HMACKey)
    file = open(encodedFilepath, 'wb')
    file.write(C)
    file.close()

    return C, IV, tag, EncKey, HMACKey, ext, encodedFilepath

def MyfileDecryptMAC(filepath, C, IV, tag, Enckey, HMACKey, ext):
    file = open(filepath, 'rb')
    content = file.read()
    file.close()
    
    message = MydecryptMAC(content, IV, EncKey, tag, HMACKey)
    
    if(ext == '.txt'):
        message = message.decode()
        file = open('..\\..\\decodedFileMAC.txt', 'w')
        file.write(message)
        file.close()
    else:
        file = open('..\\..\\decodedFileMAC.jpg', 'wb')
        file.write(message)
        file.close()
            
    return message

# =====================
# TEST
# =====================

if __name__ == "__main__":
    print("Which file do you wish to test, 1. test.txt or 2. test_image.jpg? ")
    choice = 0

    while (choice != 1 and choice != 2):
        try:
            choice = int(input())
            if (choice != 1 and choice != 2):
                print("Invalid choice")
            else:
                break
        except:
            print("Invalid data")

    if (choice == 1):
        x = MyfileEncryptMAC("..\\Test_Files\\TXT_test.txt")
        message = MyfileDecryptMAC(x[4], x[2], x[1], x[3])
        print(message)
    else:
        x = MyfileEncryptMAC("..\\Test_Files\\JPG_test.jpg")
        message = MyfileDecryptMAC(x[4], x[2], x[1], x[3])
