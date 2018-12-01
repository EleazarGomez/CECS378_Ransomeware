# Eleazar Gomez
# Dion Woo
#
# File Encryption Step 2: MyfileEncryptMAC and MyfileDecryptMAC

from os import path, urandom

from CONSTANTS import *
from MyencryptMAC import *

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac

# (C, IV, tag, Enckey, HMACKey, ext) = MyfileEncryptMAC(filepath)
#
# Modify your File Encryption to include the policy of
# Encrypt-then-MAC for every encryption.

def MyfileEncryptMAC(filepath):
    # Split the file path to extract ext
    splitFilePath = path.splitext(filepath)
    ext = splitFilePath[1]
    
    # Split the the first element of the above split to determine the
    # filename and the path of directories that led to the file
    split = splitFilePath[0].split("\\")
    filename = split[len(split) - 1]
    pathToFile = ""
    first = True

    for i in range(0, len(split) - 1):
        if first:
            first = False
        else:
            pathToFile = pathToFile + "\\"
        
        pathToFile = pathToFile + split[i]

    # Read the file
    if(ext == '.txt'):
        file = open(filepath, 'r')
        content = file.read()
        encodedContent = content.encode()
    else:
        file = open(filepath, 'rb')
        encodedContent = file.read()
        
    file.close()

    # Generate keys
    EncKey = urandom(KEY_LENGTH_BYTES)
    HMACKey = urandom(KEY_LENGTH_BYTES)

    # Encrypt
    C, IV, tag = MyencryptMAC(encodedContent, EncKey, HMACKey)

    # Return the data (pathToFile, filename, C, IV, tag, EncKey, HMACKey, ext)
    return pathToFile, filename, C, IV, tag, EncKey, HMACKey, ext

# MyfileDecryptMac(pathToFile, filename, C, IV, tag, EncKey, HMACKey, ext)
#
# Inverse of MyfileEncryptMAC. Returns the decrypted message.

def MyfileDecryptMAC(pathToFile, filename, C, IV, tag, EncKey, HMACKey, ext):
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
        file = open(pathToFile + "\\" + filename + '.txt', 'w')
        file.write(message)
        file.close()
    else:
        file = open(pathToFile + "\\" + filename + ext, 'wb')
        file.write(message)
        file.close()

    # Return the message 
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
        x, y, C, IV, tag, EncKey, HMACKey, ext = MyfileEncryptMAC("..\\Test_Files\\TXT_test.txt")
        message = MyfileDecryptMAC(x, y, C, IV, tag, EncKey, HMACKey, ext)
        print(message)
    elif (choice == 2):
        x, y, C, IV, tag, EncKey, HMACKey, ext = MyfileEncryptMAC("..\\Test_Files\\JPEG_test.jpeg")
        message = MyfileDecryptMAC(x, y, C, IV, tag, EncKey, HMACKey, ext)
    else:
        x, y, C, IV, tag, EncKey, HMACKey, ext = MyfileEncryptMAC("..\\Test_Files\\JPG_test.jpg")
        message = MyfileDecryptMAC(x, y, C, IV, tag, EncKey, HMACKey, ext)
