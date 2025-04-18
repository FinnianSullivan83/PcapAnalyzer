import json
import re

class SignatureManager:
    def __init__(self):
        self.xss_signatures = [
            re.compile(rb"<script[^>]*>", re.IGNORECASE),
            re.compile(rb"on\w+=['\"]", re.IGNORECASE),
            re.compile(rb"javascript:", re.IGNORECASE),
            re.compile(rb"alert\(", re.IGNORECASE),
            re.compile(rb"eval\(", re.IGNORECASE)
        ]
        self.sql_signatures = [
            re.compile(rb"SELECT\s", re.IGNORECASE),
            re.compile(rb"UNION\s", re.IGNORECASE),
            re.compile(rb"DROP\s", re.IGNORECASE),
            re.compile(rb"INSERT\s", re.IGNORECASE),
            re.compile(rb"OR\s+1=1", re.IGNORECASE),
            re.compile(rb"--", re.IGNORECASE),
            re.compile(rb";")
        ]
        self.cmd_signatures = [
            re.compile(rb"system\(", re.IGNORECASE),
            re.compile(rb"exec\(", re.IGNORECASE),
            re.compile(rb"cmd\.exe", re.IGNORECASE),
            re.compile(rb"/bin/sh", re.IGNORECASE)
        ]
        self.dir_signatures = [
            re.compile(rb"\.\./", re.IGNORECASE),
            re.compile(rb"\.\.\\", re.IGNORECASE),
            re.compile(rb"/etc/passwd", re.IGNORECASE),
            re.compile(rb"\\windows\\", re.IGNORECASE)
        ]
        self.malware_signatures = self.load_malware_signatures()

    def load_malware_signatures(self):
        try:
            with open("resources/malware_signatures.json", "r", encoding="utf-8") as f:
                return {key: [sig.encode('utf-8') if isinstance(sig, str) else sig for sig in sigs] 
                        for key, sigs in json.load(f).items()}
        except Exception as e:
            print(f"Ошибка загрузки сигнатур: {str(e)}. Используются сигнатуры по умолчанию.")
            return {
                "emotet": [b"POST /api/", b"Content-Type: application/octet-stream"],
                "dridex": [b".dll", b"GET /files/"],
                "c2_beacon": [b"HTTP/1.1 200 OK", b"Connection: keep-alive", b"ping"]
            }

    def update_signatures(self, source_url=None):
        pass
