import os
from cryptography.fernet import Fernet

ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY").encode()

def decrypt_api_key(encrypted_key: str) -> str:
    cipher = Fernet(ENCRYPTION_KEY)
    return cipher.decrypt(encrypted_key.encode()).decode()
