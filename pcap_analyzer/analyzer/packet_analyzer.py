# pcap_analyzer/analyzer/packet_analyzer.py

import os
import hashlib
import aiohttp
import asyncio
import datetime
from typing import Optional, Dict, Any, List, Tuple
from scapy.all import PcapReader, TCP, UDP, IP, ICMP, DNSQR, Raw, wrpcap
from concurrent.futures import ThreadPoolExecutor
import geoip2.database

from .analysis_result import AnalysisResult
from .signature_manager import SignatureManager

class PacketAnalyzer:
    def __init__(self, pcap_file: str, extracted_files_dir: str, vt_api_key: str, use_vt: bool, log_callback, config):
        self.pcap_file = pcap_file
        self.extracted_files_dir = extracted_files_dir
        self.vt_api_key = vt_api_key
        self.use_vt = use_vt
        self.log_callback = log_callback
        self.config = config
        self.total_packets = 0
        self.analyzed_packets = 0
        self.running = True
        self.signatures = SignatureManager()
        self.geoip_cache: Dict[str, str] = {}
        self.suspicious_packets = []
        self.file_hash_cache = set()
        self.vt_checked = False

    def count_packets(self) -> None:
        with PcapReader(self.pcap_file) as packets:
            self.total_packets = sum(1 for _ in packets if self.running)
        self.log_callback(f"Всего пакетов: {self.total_packets}")

    def extract_file_from_packet(self, pkt, file_counter: int) -> Tuple[Optional[str], Optional[str]]:
        if pkt.haslayer(Raw) and b"HTTP/1.1 200 OK" in pkt[Raw].load:
            payload = pkt[Raw].load
            file_hash = hashlib.sha256(payload).hexdigest()
            if file_hash in self.file_hash_cache:
                self.log_callback(f"Дубликат файла с хэшем {file_hash[:8]} пропущен", level="DEBUG")
                return None, file_hash
            content_type = b"Content-Type: "
            if content_type in payload:
                ct_index = payload.index(content_type) + len(content_type)
                ct_end = payload.index(b"\r\n", ct_index)
                ct_value = payload[ct_index:ct_end]
                if any(b in ct_value for b in [b"application", b"octet-stream"]) or b".exe" in payload or b".pdf" in payload or b".dll" in payload:
                    body_start = payload.index(b"\r\n\r\n") + 4
                    file_data = payload[body_start:]
                    if len(file_data) > 0:
                        file_path = os.path.join(self.extracted_files_dir, f"file_{file_hash[:8]}.bin")
                        if not os.path.exists(file_path):
                            file_ext = ".bin"
                            if b"application/x-msdownload" in ct_value or b"exe" in ct_value or b".exe" in payload:
                                file_ext = ".exe"
                            elif b"application/pdf" in ct_value or b"pdf" in ct_value or b".pdf" in payload:
                                file_ext = ".pdf"
                            elif b"application/x-dosexec" in ct_value or b"dll" in ct_value or b".dll" in payload:
                                file_ext = ".dll"
                            if b"GET" in payload:
                                url_end = payload.index(b"HTTP/1.")
                                url = payload[4:url_end].strip()
                                if url.endswith(b".exe"):
                                    file_ext = ".exe"
                                elif url.endswith(b".pdf"):
                                    file_ext = ".pdf"
                                elif url.endswith(b".dll"):
                                    file_ext = ".dll"
                            file_name = f"file_{file_hash[:8]}{file_ext}"
                            file_path = os.path.join(self.extracted_files_dir, file_name)
                            with open(file_path, "wb") as f:
                                f.write(file_data)
                            self.log_callback(f"Извлечён файл: {file_name}")
                            self.file_hash_cache.add(file_hash)
                        return file_path, file_hash
        return None, None

    async def check_virustotal_async(self, file_hash: str, session: aiohttp.ClientSession) -> Optional[Dict[str, int]]:
        if not self.use_vt:
            if not self.vt_checked:
                self.log_callback("Проверка VirusTotal отключена для всех файлов", level="DEBUG")
                self.vt_checked = True
            return None

        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": self.vt_api_key}
        retries = 3
        delay = 2  # начальное время задержки в секундах
        for attempt in range(retries):
            try:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        result: Dict[str, Any] = await response.json()
                        stats = result["data"]["attributes"]["last_analysis_stats"]
                        positives = stats["malicious"] + stats["suspicious"]
                        total = sum(stats.values())
                        self.log_callback(f"VirusTotal для {file_hash[:8]}: {positives}/{total} детектов", level="DEBUG")
                        return {"positives": positives, "total": total}
                    elif response.status == 404:
                        self.log_callback(f"Файл {file_hash[:8]} не найден в VirusTotal.", level="DEBUG")
                        return {"positives": 0, "total": 0}
                    else:
                        self.log_callback(f"Попытка {attempt + 1}: ошибка {response.status} для {file_hash[:8]}", level="WARNING")
            except Exception as e:
                self.log_callback(f"Попытка {attempt + 1}: исключение для {file_hash[:8]}: {str(e)}", level="ERROR")
            await asyncio.sleep(delay)
            delay *= 2

        self.log_callback(f"VirusTotal проверка для {file_hash[:8]} не удалась после {retries} попыток", level="ERROR")
        return None

    async def check_virustotal_batch(self, file_hashes: List[str]) -> List:
        async with aiohttp.ClientSession() as session:
            tasks = [self.check_virustotal_async(file_hash, session) for file_hash in file_hashes]
            return await asyncio.gather(*tasks)

    def get_geoip_location(self, ip: str) -> str:
        if ip in self.geoip_cache:
            return self.geoip_cache[ip]
        try:
            with geoip2.database.Reader('resources/GeoLite2-City.mmdb') as reader:
                response = reader.city(ip)
                location = f"{response.city.name or 'Unknown'}, {response.country.name or 'Unknown'}"
                self.geoip_cache[ip] = location
                return location
        except Exception as e:
            self.log_callback(f"Ошибка получения локации для {ip}: {str(e)}", level="ERROR")
            return "Unknown location"

    def analyze_chunk(self, packets_chunk, result: AnalysisResult) -> None:
        file_counter = 0
        file_hashes = []
        dns_requests = {}
        for pkt_idx, pkt in enumerate(packets_chunk):
            if not self.running:
                break
            packet_num = self.analyzed_packets + 1
            self.analyzed_packets += 1
            if pkt.haslayer(IP):
                ip_src = pkt[IP].src
                ip_dst = pkt[IP].dst
                result.ip_counter[ip_src] += 1
                result.ip_counter[ip_dst] += 1
                result.traffic_direction[ip_src]['out'] += 1
                result.traffic_direction[ip_dst]['in'] += 1

                if not result.ip_locations[ip_src]:
                    result.ip_locations[ip_src] = self.get_geoip_location(ip_src)

                timestamp = datetime.datetime.fromtimestamp(float(pkt.time))
                time_key = timestamp.strftime('%Y-%m-%d %H:%M')
                result.time_windows[time_key]['total'] += 1
                pkt_time_str = timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')

                if pkt.haslayer(TCP):
                    result.port_counter[pkt[TCP].sport] += 1
                    result.port_counter[pkt[TCP].dport] += 1
                    result.protocol_counter['TCP'] += 1
                    result.time_windows[time_key]['TCP'] += 1
                    result.ip_protocols[ip_src]['TCP'] += 1
                    result.ip_protocols[ip_dst]['TCP'] += 1
                    if pkt[TCP].dport == 22 and pkt.haslayer(Raw):
                        result.ssh_attempts[ip_src].append(pkt_time_str)
                        if len(result.ssh_attempts[ip_src]) > 10:
                            result.suspicious_ips[ip_src] += len(result.ssh_attempts[ip_src])
                elif pkt.haslayer(UDP):
                    result.port_counter[pkt[UDP].sport] += 1
                    result.port_counter[pkt[UDP].dport] += 1
                    result.protocol_counter['UDP'] += 1
                    result.time_windows[time_key]['UDP'] += 1
                    result.ip_protocols[ip_src]['UDP'] += 1
                    result.ip_protocols[ip_dst]['UDP'] += 1
                elif pkt.haslayer(ICMP):
                    result.protocol_counter['ICMP'] += 1
                    result.time_windows[time_key]['ICMP'] += 1
                    result.ip_protocols[ip_src]['ICMP'] += 1
                    result.ip_protocols[ip_dst]['ICMP'] += 1
                    result.icmp_counter += 1

                if pkt.haslayer(DNSQR):
                    try:
                        qname = pkt[DNSQR].qname.decode(errors='ignore')
                        result.dns_queries[qname] += 1
                        dns_requests[ip_src] = {"domain": qname, "time": pkt_time_str, "packet_num": packet_num}
                    except Exception:
                        continue

                if pkt.haslayer(Raw):
                    payload = pkt[Raw].load
                    if len(payload) < 10:
                        continue
                    payload_lower = payload.lower()
                    if b"http" in payload_lower and (b"200 ok" in payload_lower or b".exe" in payload_lower or b".pdf" in payload_lower):
                        result.http_downloads[f"{ip_src} -> {ip_dst}"] += 1
                        file_path, file_hash = self.extract_file_from_packet(pkt, file_counter)
                        if file_path and file_hash:
                            file_counter += 1
                            file_hashes.append(file_hash)
                            result.extracted_files.append({
                                "path": file_path,
                                "hash": file_hash,
                                "source_ip": ip_src,
                                "dest_ip": ip_dst,
                                "vt_result": None
                            })
                        if ip_src in dns_requests and abs((timestamp - datetime.datetime.strptime(dns_requests[ip_src]["time"], '%Y-%m-%d %H:%M:%S.%f')).total_seconds()) < 60:
                            result.attack_sequences[ip_src].append({
                                "type": "DNS_to_HTTP",
                                "dns_packet": dns_requests[ip_src]["packet_num"],
                                "dns_domain": dns_requests[ip_src]["domain"],
                                "http_packet": packet_num,
                                "http_payload": payload.decode(errors='ignore')[:100]
                            })

                    suspicious = False
                    for sig in self.signatures.xss_signatures:
                        if sig.search(payload_lower):
                            result.xss_detected[ip_src].append({
                                "packet_num": packet_num,
                                "timestamp": pkt_time_str,
                                "payload": payload.decode(errors='ignore')[:100]
                            })
                            result.suspicious_ips[ip_src] += 1
                            suspicious = True
                            break
                    for sig in self.signatures.sql_signatures:
                        if sig.search(payload_lower):
                            result.sql_detected[ip_src].append({
                                "packet_num": packet_num,
                                "timestamp": pkt_time_str,
                                "payload": payload.decode(errors='ignore')[:100]
                            })
                            result.suspicious_ips[ip_src] += 1
                            suspicious = True
                            break
                    for sig in self.signatures.cmd_signatures:
                        if sig.search(payload_lower):
                            result.cmd_detected[ip_src].append({
                                "packet_num": packet_num,
                                "timestamp": pkt_time_str,
                                "payload": payload.decode(errors='ignore')[:100]
                            })
                            result.suspicious_ips[ip_src] += 1
                            suspicious = True
                            break
                    for sig in self.signatures.dir_signatures:
                        if sig.search(payload_lower):
                            result.dir_detected[ip_src].append({
                                "packet_num": packet_num,
                                "timestamp": pkt_time_str,
                                "payload": payload.decode(errors='ignore')[:100]
                            })
                            result.suspicious_ips[ip_src] += 1
                            suspicious = True
                            break
                    for malware, sigs in self.signatures.malware_signatures.items():
                        if any(sig in payload for sig in sigs):
                            result.malware_detected[ip_src][malware] += 1
                            result.suspicious_ips[ip_src] += 1
                            suspicious = True

                    if suspicious:
                        self.suspicious_packets.append(pkt)

        if file_hashes:
            vt_results = asyncio.run(self.check_virustotal_batch(file_hashes))
            for i, vt_result in enumerate(vt_results):
                for file_info in result.extracted_files:
                    if file_info["hash"] == file_hashes[i]:
                        file_info["vt_result"] = vt_result
                        break

    def analyze_packets(self, progress_callback) -> AnalysisResult:
        """
        Анализирует все пакеты из PCAP-файла с разбивкой на чанки.
        Вызывает progress_callback с прогрессом обработки.
        Возвращает объект AnalysisResult с итоговыми данными анализа.
        """
        result = AnalysisResult()
        if self.total_packets == 0:
            self.count_packets()
        if not self.running:
            return result

        chunk_size = 100
        batch = []
        with PcapReader(self.pcap_file) as packets:
            with ThreadPoolExecutor(max_workers=int(self.config['DEFAULT']['max_workers'])) as executor:
                futures = []
                for pkt in packets:
                    if not self.running:
                        break
                    batch.append(pkt)
                    if len(batch) >= chunk_size:
                        futures.append(executor.submit(self.analyze_chunk, batch.copy(), result))
                        progress_callback(self.analyzed_packets, self.total_packets)
                        batch.clear()
                if batch:
                    futures.append(executor.submit(self.analyze_chunk, batch.copy(), result))
                for future in futures:
                    future.result()

        if self.suspicious_packets:
            from scapy.all import wrpcap
            output_pcap = os.path.join(self.extracted_files_dir, "suspicious.pcap")
            wrpcap(output_pcap, self.suspicious_packets)
            self.log_callback(f"Экспортировано {len(self.suspicious_packets)} подозрительных пакетов в {output_pcap}")

        return result
