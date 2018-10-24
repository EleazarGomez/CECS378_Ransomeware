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
    ext = splitFilePath[1]
    
    if(ext == '.txt'):
        file = open(filepath, 'r')
        content = file.read()
        encodedContent = content.encode()
        encodedFilepath = '..\\..\\encodedFile.txt'
    else:
        file = open(filepath, 'rb')
        encodedContent = file.read()
        encodedFilepath = '..\\..\\encodedFile' + ext
        
    file.close()

    # Generate keys
    EncKey = os.urandom(KEY_LENGTH_BYTES)
    HMACKey = os.urandom(KEY_LENGTH_BYTES)

    # Encrypt
    C, IV, tag = MyencryptMAC(encodedContent, EncKey, HMACKey)

    # Convert data to strings
    CString = binascii.hexlify(C).decode('utf-8')
    IVString = binascii.hexlify(IV).decode('utf-8')
    EncKeyString = binascii.hexlify(EncKey).decode('utf-8')
    HMACKeyString = binascii.hexlify(HMACKey).decode('utf-8')
    tagString = binascii.hexlify(tag).decode('utf-8')

    # Store in JSON
    data = {'C': CString, 'IV': IVString, 'tag': tagString,
            'EncKey': EncKeyString, 'HMACKey': HMACKeyString, 'ext': ext}

    file = open('..\\..\\data.json', 'w')
    json.dump(data, file)
    file.close()

    # Output
    file = open(encodedFilepath, 'wb')
    file.write(C)
    file.close()
    
    return C, IV, tag, EncKey, HMACKey, ext

def MyfileDecryptMAC():
    # Read data from JSON
    file = open('..\\..\\data.json', 'r')
    data = json.load(file)
    file.close()

    # Convert data to bytes
    C = binascii.unhexlify(data['C'].encode('utf-8'))
    IV = binascii.unhexlify(data['IV'].encode('utf-8'))
    tag = binascii.unhexlify(data['tag'].encode('utf-8'))
    EncKey = binascii.unhexlify(data['EncKey'].encode('utf-8'))
    HMACKey = binascii.unhexlify(data['HMACKey'].encode('utf-8'))
    ext = data['ext']

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
        file = open('..\\..\\decodedFile.txt', 'w')
        file.write(message)
        file.close()
    else:
        file = open('..\\..\\decodedFile' + ext, 'wb')
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
        x = MyfileEncryptMAC("..\\Test_Files\\TXT_test.txt")
        message = MyfileDecryptMAC()
        print(message)
    elif (choice == 2):
        x = MyfileEncryptMAC("..\\Test_Files\\JPEG_test.jpeg")
        message = MyfileDecryptMAC()
    else:
        x = MyfileEncryptMAC("..\\Test_Files\\JPG_test.jpg")
        message = MyfileDecryptMAC()
