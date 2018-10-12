import os

from CONSTANTS import *
from Myencrypt import *

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

def MyfileEncrypt(filepath):
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
        encodedFilepath = '..\\..\\encodedFile.jpg'
        
    file.close()
    
    key = os.urandom(KEY_LENGTH_BYTES)
    
    C, IV = Myencrypt(encodedContent, key)
    
    file = open(encodedFilepath, 'wb')
    file.write(C)
    file.close()
    
    return C, IV, key, ext, encodedFilepath

def MyfileDecrypt(filepath, key, IV, ext):
    file = open(filepath, 'rb')
    content = file.read()
    file.close()
    
    message = Mydecrypt(content, key, IV)
    
    if(ext == '.txt'):
        message = message.decode()
        file = open('..\\..\\decodedFile.txt', 'w')
        file.write(message)
        file.close()
    else:
        file = open('..\\..\\decodedFile.jpg', 'wb')
        file.write(message)
        file.close()
            
    return message

# =====================
# TEST
# =====================

if __name__ == "__main__":
    print("Which file do you wish to test, 1. test.txt or 2. test_image.jpg? ")
    choice = int(input())

    if (choice == 1):
        x = MyfileEncrypt("..\\Test_Files\\test.txt")
        message = MyfileDecrypt(x[4], x[2], x[1], x[3])
        print(message)
    else:
        x = MyfileEncrypt("..\\Test_Files\\test_image.jpg")
        message = MyfileDecrypt(x[4], x[2], x[1], x[3])
