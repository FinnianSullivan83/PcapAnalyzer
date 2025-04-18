import html

def generate_summary(data):
    if not data:
        return "<p>Нет данных для отображения.</p>"
    top_ip = html.escape(data.get("top_active_ips", [{}])[0].get("ip", "N/A"))
    top_ip_packets = data.get("top_active_ips", [{}])[0].get("packets", "N/A")
    total_packets = data.get("total_packets", "N/A")
    duration = html.escape(data.get("duration", "N/A"))
    key_findings = data.get("key_findings") or {}
    total_threats = key_findings.get("total_threats", "N/A")
    return f"""
    <div class='summary'>
        <h2>Ключевые выводы</h2>
        <ul>
            <li>Обработано {total_packets} пакетов за {duration}.</li>
            <li>Основной источник трафика: {top_ip} ({top_ip_packets} пакетов).</li>
            <li>Всего угроз: {total_threats}.</li>
        </ul>
    </div>
    """

def generate_tables(data):
    if not data:
        return "<p>Нет таблиц для отображения.</p>"
    suspicious_rows = ''.join(
        f"<tr><td>{html.escape(ip['ip'])}</td><td>{html.escape(', '.join(ip['reasons']))}</td><td>{html.escape(ip['location'])}</td></tr>"
        for ip in data.get("suspicious_ips", [])
    )
    file_rows = ''.join(
        f"<tr><td>{html.escape(f['path'].split('/')[-1])}</td>"
        f"<td>{html.escape(f['hash'][:8])}...</td>"
        f"<td>{html.escape(f['source_ip'])}</td>"
        f"<td>{html.escape(f['dest_ip'])}</td>"
        f"<td>{html.escape(str(f.get('vt_result', {}).get('positives', 'Не проверено')))}</td></tr>"
        for f in data.get("extracted_files", [])
    )
    return f"""
    <h2>Подозрительные IP</h2>
    <table border="1">
        <thead><tr><th>IP</th><th>Причины</th><th>Локация</th></tr></thead>
        <tbody>{suspicious_rows}</tbody>
    </table>
    <h2>Извлечённые файлы</h2>
    <table border="1">
        <thead><tr><th>Файл</th><th>SHA256</th><th>Источник</th><th>Назначение</th><th>VirusTotal</th></tr></thead>
        <tbody>{file_rows}</tbody>
    </table>
    """

def generate_charts(data):
    return "<div class='chart-container'><em>Графики временно не отображаются в offline-версии отчёта.</em></div>"
