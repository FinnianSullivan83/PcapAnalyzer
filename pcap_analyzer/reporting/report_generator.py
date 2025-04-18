import os
import datetime
from collections import Counter

class ReportGenerator:
    def __init__(self, pcap_file, start_time, end_time, total_packets, ip_threshold, port_threshold):
        self.pcap_file = pcap_file
        self.start_time = start_time
        self.end_time = end_time
        self.total_packets = total_packets
        self.ip_threshold = ip_threshold
        self.port_threshold = port_threshold

    def generate(self, analysis_result):
        report = "=== PCAP Analysis Report ===\n\n"
        duration = "Не завершено"
        if self.start_time:
            end = self.end_time if self.end_time else datetime.datetime.now()
            duration_sec = (end - self.start_time).total_seconds()
            duration = f"{int(duration_sec // 60)} мин {int(duration_sec % 60)} сек"

        report_data = {
            "file": os.path.basename(self.pcap_file),
            "date": str(datetime.datetime.now()),
            "total_packets": self.total_packets,
            "analysis_started": str(self.start_time),
            "analysis_ended": str(self.end_time) if self.end_time else "Остановлен",
            "duration": duration,
            "ssh_bruteforce_attempts": [],
            "suspicious_ips": [],
            "dns_queries": [],
            "http_downloads": [],
            "peak_activity": [],
            "xss_attacks": [],
            "sql_injections": [],
            "cmd_injections": [],
            "dir_traversals": [],
            "attack_sequences": [],
            "top_active_ips": [],
            "top_ports": [],
            "protocol_usage": dict(analysis_result.protocol_counter),
            "icmp_packets": analysis_result.icmp_counter,
            "threat_summary": {},
            "ip_locations": dict(analysis_result.ip_locations),
            "malware_detected": [],
            "extracted_files": analysis_result.extracted_files,
            "attack_timeline": [],
            "recommendations": []
        }

        top_ip = max(analysis_result.ip_counter, key=analysis_result.ip_counter.get, default="N/A")
        total_threats = sum(sum(counts.values()) for counts in analysis_result.malware_detected.values()) + \
                        sum(len(attacks) for attacks in analysis_result.xss_detected.values() if isinstance(attacks, list)) + \
                        sum(len(attacks) for attacks in analysis_result.sql_detected.values() if isinstance(attacks, list))
        report += "--- Ключевые выводы ---\n"
        report += f"Обработано {self.total_packets} пакетов за {duration}.\n"
        report += f"Основной источник трафика: {top_ip} ({analysis_result.ip_counter[top_ip]} пакетов).\n"
        report += f"Всего угроз: {total_threats}.\n\n"
        report_data["key_findings"] = {
            "total_packets": self.total_packets,
            "duration": duration,
            "top_ip": top_ip,
            "top_ip_packets": analysis_result.ip_counter[top_ip],
            "total_threats": total_threats
        }

        report += f"Файл: {os.path.basename(self.pcap_file)}\n"
        report += f"Дата: {datetime.datetime.now()}\n"
        report += f"Всего пакетов: {self.total_packets}\n"
        report += f"Анализ начат: {self.start_time}\n"
        report += f"Анализ завершен: {self.end_time if self.end_time else 'Остановлен'}\n"
        report += f"Длительность анализа: {duration}\n\n"

        report += "--- Подозрительные IP ---\n"
        if analysis_result.suspicious_ips:
            for ip, count in analysis_result.suspicious_ips.most_common():
                if analysis_result.ip_counter[ip] >= self.ip_threshold:
                    reasons = []
                    if ip in analysis_result.ssh_attempts and len(analysis_result.ssh_attempts[ip]) > 10:
                        reasons.append(f"SSH brute-force: {len(analysis_result.ssh_attempts[ip])}")
                    if ip in analysis_result.xss_detected and analysis_result.xss_detected[ip]:
                        reasons.append(f"XSS: {len(analysis_result.xss_detected[ip])}")
                    if ip in analysis_result.sql_detected and analysis_result.sql_detected[ip]:
                        reasons.append(f"SQL injection: {len(analysis_result.sql_detected[ip])}")
                    if ip in analysis_result.malware_detected:
                        malware_str = ", ".join([f"{m}: {c}" for m, c in analysis_result.malware_detected[ip].items()])
                        reasons.append(f"Malware: {malware_str}")
                    if reasons:
                        report += f" - {ip} ({analysis_result.ip_locations[ip]}): {', '.join(reasons)}\n"
                        report_data["suspicious_ips"].append({"ip": ip, "reasons": reasons, "location": analysis_result.ip_locations[ip]})
        else:
            report += "Не обнаружено.\n"

        report += "\n--- Извлечённые файлы ---\n"
        if analysis_result.extracted_files:
            from collections import Counter
            file_dest_counts = Counter()
            for file_info in analysis_result.extracted_files:
                file_dest_counts[(file_info["source_ip"], file_info["dest_ip"])] += 1
            for (src_ip, dst_ip), count in file_dest_counts.most_common():
                file_hash = next(f["hash"] for f in analysis_result.extracted_files if f["source_ip"] == src_ip and f["dest_ip"] == dst_ip)
                vt_str = "Не проверено"
                for f in analysis_result.extracted_files:
                    if f["hash"] == file_hash and f["vt_result"]:
                        vt_str = f"{f['vt_result']['positives']}/{f['vt_result']['total']}"
                        break
                report += f" - file_{file_hash[:8]}.bin (SHA256: {file_hash[:8]}...): {src_ip} -> {dst_ip} ({count} раз), VT: {vt_str}\n"
        else:
            report += "Не извлечено.\n"

        report += "\n--- Обнаруженная малварь ---\n"
        if analysis_result.malware_detected:
            for ip, malwares in analysis_result.malware_detected.items():
                report += f" - {ip}: {', '.join([f'{m}: {c}' for m, c in malwares.items()])}\n"
                report_data["malware_detected"].extend({"ip": ip, "malware": m, "count": c} for m, c in malwares.items())
        else:
            report += "Не обнаружено.\n"

        report += "\n--- Топ активных IP (Топ 5) ---\n"
        for ip, count in analysis_result.ip_counter.most_common(5):
            if count >= self.ip_threshold:
                proto_breakdown = ", ".join([f"{proto}: {cnt}" for proto, cnt in analysis_result.ip_protocols[ip].items()])
                report += f" - {ip} ({analysis_result.ip_locations[ip]}): {count} пакетов ({proto_breakdown})\n"
                report_data["top_active_ips"].append({"ip": ip, "packets": count, "protocols": dict(analysis_result.ip_protocols[ip]), "location": analysis_result.ip_locations[ip]})
        report += "\n--- Использование протоколов ---\n"
        total_proto = sum(analysis_result.protocol_counter.values())
        for proto, count in analysis_result.protocol_counter.items():
            percent = (count / total_proto) * 100 if total_proto > 0 else 0
            report += f" - {proto}: {count} пакетов ({percent:.1f}%)\n"
        report += "\n--- Рекомендации ---\n"
        recommendations = []
        if analysis_result.malware_detected:
            high_risk_ip = max(analysis_result.suspicious_ips, key=analysis_result.suspicious_ips.get, default=None)
            if high_risk_ip:
                recommendations.append(f"Блокировать IP {high_risk_ip} из-за высокой активности угроз.")
        if total_threats > 100:
            recommendations.append("Провести аудит безопасности сети из-за большого количества угроз.")
        if not any(f["vt_result"] for f in analysis_result.extracted_files):
            recommendations.append("Включить проверку VirusTotal для анализа извлечённых файлов.")
        report += "\n".join(f" - {rec}" for rec in recommendations) + "\n" if recommendations else "Нет рекомендаций.\n"
        report_data["recommendations"] = recommendations

        report += "\n=== Конец отчета ===\n"
        return report, report_data
