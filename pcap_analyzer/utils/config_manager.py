import configparser
from pcap_analyzer.utils.encryption import decrypt_api_key

def load_config(config_path: str = 'config.ini') -> configparser.ConfigParser:
    config = configparser.ConfigParser()
    config.read(config_path)
    vt_api_key_value = config['DEFAULT'].get('vt_api_key', '')
    if vt_api_key_value.startswith("encrypted:"):
        encrypted_key = vt_api_key_value.split("encrypted:")[1]
        config['DEFAULT']['vt_api_key'] = decrypt_api_key(encrypted_key)
    return config
