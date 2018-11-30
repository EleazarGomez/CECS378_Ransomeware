import os

from MyRSAEncrypt import *
from CONSTANTS import *


def Decrypt(fileInfo):
    for item in fileInfo:
        MyRSADecrypt(item[0], item[1], RSA_PRIVATE_KEY_FILEPATH)
        os.remove(item[0] + "\\" + item[1] + ".json")
