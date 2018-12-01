# Eleazar Gomez
# Dion Woo
#
# File Encryption Step 1: MyfileEncrypt and MyfileDecrypt

from os import path, urandom

from CONSTANTS import *
from Myencrypt import *


# (C, IV, key, ext) = MyfileEncrypt (filepath):
#
# In this method, you'll generate a 32 Byte key. You open and read the
# file as a string. You then call the above method to encrypt your file
# using the key you generated. You return the cipher C, IV, key and the
# extension of the file (as a string).

def MyfileEncrypt(filepath):
    # Split filepath into path and ext and retrieve ext
    splitFilePath = path.splitext(filepath)
    ext = splitFilePath[1]
    
    # If the file is a text file, read the content and then encode.
    # Otherwise, read the file as bytes. Create a filepath to store
    # the encoded file.
    if(ext == '.txt'):
        file = open(filepath, 'r')
        content = file.read()
        encodedContent = content.encode()
        encryptedFilepath = '..\\..\\encryptedFile.txt'
    else:
        file = open(filepath, 'rb')
        encodedContent = file.read()
        encryptedFilepath = '..\\..\\encryptedFile' + ext
    file.close()

    # Generate a random 32 byte key
    key = urandom(KEY_LENGTH_BYTES)

    # Pass the encoded content and key to Myencrypt and retrieve the C and IV
    C, IV = Myencrypt(encodedContent, key)

    # Create encrypted file
    file = open(encryptedFilepath, 'wb')
    file.write(C)
    file.close()

    # Return data (C, IV, key, ext, encryptedFilepath)
    return C, IV, key, ext, encryptedFilepath

# message = MyfileDecrypt(filepath, key, IV, ext)
#
# Inverse of MyfileEncrypt. Returns the decrypted message.

def MyfileDecrypt(filepath, key, IV, ext):
    # Read the byte data from the encrypted file
    file = open(filepath, 'rb')
    content = file.read()
    file.close()

    # Decrypt the file
    message = Mydecrypt(content, key, IV)

    # Create the decrypted file
    if(ext == '.txt'):
        message = message.decode()
        file = open('..\\..\\decryptedFile.txt', 'w')
        file.write(message)
        file.close()
    else:
        file = open('..\\..\\decryptedFile.jpg', 'wb')
        file.write(message)
        file.close()

    # Return the message
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
                print("Invalide choice")
            else:
                break
        except:
            print("Invalid data")

    if (choice == 1):
        x = MyfileEncrypt("..\\Test_Files\\TXT_test.txt")
        message = MyfileDecrypt(x[4], x[2], x[1], x[3])
        print(message)
    else:
        x = MyfileEncrypt("..\\Test_Files\\JPG_test.jpg")
        message = MyfileDecrypt(x[4], x[2], x[1], x[3])
