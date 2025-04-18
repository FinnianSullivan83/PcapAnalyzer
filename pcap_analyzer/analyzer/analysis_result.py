from collections import defaultdict, Counter

class AnalysisResult:
    def __init__(self):
        self.ssh_attempts = defaultdict(list)
        self.suspicious_ips = Counter()
        self.dns_queries = Counter()
        self.http_downloads = Counter()
        self.ip_counter = Counter()
        self.port_counter = Counter()
        self.protocol_counter = Counter()
        self.icmp_counter = 0
        self.traffic_direction = defaultdict(lambda: {'in': 0, 'out': 0})
        self.time_windows = defaultdict(lambda: {'total': 0, 'TCP': 0, 'UDP': 0, 'ICMP': 0})
        self.ip_protocols = defaultdict(lambda: Counter())
        self.ip_locations = defaultdict(str)
        self.extracted_files = []
        self.xss_detected = defaultdict(list)
        self.sql_detected = defaultdict(list)
        self.cmd_detected = defaultdict(list)
        self.dir_detected = defaultdict(list)
        self.malware_detected = defaultdict(Counter)
        self.attack_sequences = defaultdict(list)
