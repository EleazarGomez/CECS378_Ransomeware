from Encrypt import *
from Decrypt import *     
    

# =====================
# TEST
# =====================

if __name__ == "__main__":
    print("Press Enter to Encrypt: ")
    input()
    fileInfo = Encrypt()
    print("Press Enter to Decrypt: ")
    input()
    Decrypt(fileInfo)
