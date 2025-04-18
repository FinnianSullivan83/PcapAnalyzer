from cryptography.fernet import Fernet

ENCRYPTION_KEY = b'dFHILvc_xdB_-D5mjTR3QLPESnEcqK0e2GjXH_FC-jo='

def decrypt_api_key(encrypted_key: str) -> str:
    cipher = Fernet(ENCRYPTION_KEY)
    return cipher.decrypt(encrypted_key.encode()).decode()
