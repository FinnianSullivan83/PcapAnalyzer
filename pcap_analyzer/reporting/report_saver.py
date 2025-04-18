import os
import json
import csv
import html
import matplotlib.pyplot as plt
import io
import asyncio
import aiofiles
import htmlmin
import time
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from pcap_analyzer.reporting.report_preprocessor import preprocess_report_data

def profile(func):
    def wrapper(*args, **kwargs):
        start = time.perf_counter()
        result = func(*args, **kwargs)
        elapsed = time.perf_counter() - start
        logger = kwargs.get("logger", None)
        if logger:
            logger.debug(f"{func.__name__} выполнена за {elapsed:.4f} секунд")
        return result
    return wrapper

class ReportSaver:
    @staticmethod
    @profile
    def save(format_type, file_path, report_text, report_data, logger):
        savers = {
            "PDF": ReportSaver.save_pdf,
            "JSON": ReportSaver.save_json,
            "CSV": ReportSaver.save_csv,
            "TXT": ReportSaver.save_txt,
            "HTML": ReportSaver.save_html
        }
        saver = savers.get(format_type)
        if saver:
            os.makedirs(os.path.dirname(file_path) or '.', exist_ok=True)
            saver(file_path, report_text, report_data, logger)
        else:
            raise ValueError(f"Неподдерживаемый формат: {format_type}")

    @staticmethod
    @profile
    def save_pdf(file_path, report_text, report_data, logger):
        try:
            font_path = 'resources/DejaVuSans.ttf'
            if not os.path.exists(font_path):
                raise FileNotFoundError(f"Шрифт не найден: {font_path}")
            pdfmetrics.registerFont(TTFont('DejaVuSans', font_path))
            doc = SimpleDocTemplate(file_path, pagesize=letter)
            styles = getSampleStyleSheet()
            styles['BodyText'].fontName = 'DejaVuSans'
            story = []
            for line in report_text.split("\n"):
                if line.strip():
                    story.append(Paragraph(line, styles["BodyText"]))
                    story.append(Spacer(1, 6))
            if report_data.get("peak_activity"):
                plt.figure(figsize=(10, 4))
                times = [item["time"] for item in report_data["peak_activity"][:5]]
                totals = [item["total"] for item in report_data["peak_activity"][:5]]
                plt.plot(range(len(times)), totals, 'b-', label="Packets")
                plt.xticks(range(len(times)), times, rotation=45)
                plt.title("Peak Activity Over Time")
                plt.xlabel("Time")
                plt.ylabel("Packets")
                plt.legend()
                plt.tight_layout()
                buf = io.BytesIO()
                plt.savefig(buf, format='png', dpi=100)
                buf.seek(0)
                story.append(Image(buf, width=400, height=150))
                plt.close()
            doc.build(story)
            if 'buf' in locals():
                buf.close()
            if logger:
                logger.info(f"PDF report saved: {file_path}")
        except Exception as e:
            if logger:
                logger.exception(f"PDF save error: {str(e)}")
            if 'buf' in locals():
                buf.close()
            raise

    @staticmethod
    def save_json(file_path, report_text, report_data, logger=None, cef=False):
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                if cef:
                    for item in report_data.get("suspicious_ips", []):
                        ip = item.get("ip", "N/A")
                        reasons = ", ".join(item.get("reasons", []))
                        location = item.get("location", "Unknown")
                        cef_line = f"CEF:0|PCAPAnalyzer|Analyzer|1.0|100|Suspicious IP|5|src={ip} msg={reasons} loc={location}"
                        f.write(cef_line + "\n")
                else:
                    json.dump(report_data, f, ensure_ascii=False, indent=4)
            if logger:
                logger.info(f"JSON report saved: {file_path}")
        except Exception as e:
            if logger:
                logger.exception(f"JSON save error: {str(e)}")
            raise

    @staticmethod
    @profile
    def save_csv(file_path, report_text, report_data, logger):
        try:
            with open(file_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Section", "Data"])
                writer.writerow(["File", report_data.get("file", "N/A")])
                writer.writerow(["Date", report_data.get("date", "N/A")])
                writer.writerow(["Total Packets", report_data.get("total_packets", "N/A")])
                writer.writerow(["Analysis Started", report_data.get("analysis_started", "N/A")])
                writer.writerow(["Analysis Ended", report_data.get("analysis_ended", "N/A")])
                writer.writerow(["Duration", report_data.get("duration", "N/A")])
                writer.writerow([])
                writer.writerow(["Suspicious IPs"])
                writer.writerow(["IP", "Reasons", "Location"])
                for item in report_data.get("suspicious_ips", []):
                    writer.writerow([item.get("ip", "N/A"),
                                     ", ".join(item.get("reasons", [])),
                                     item.get("location", "N/A")])
                writer.writerow([])
                writer.writerow(["Extracted Files"])
                writer.writerow(["File Name", "SHA256", "Source IP", "Dest IP", "VirusTotal Positives", "VirusTotal Total"])
                for item in report_data.get("extracted_files", []):
                    vt_result = item.get("vt_result", {})
                    vt_pos = vt_result.get("positives", "N/A") if vt_result else "N/A"
                    vt_tot = vt_result.get("total", "N/A") if vt_result else "N/A"
                    writer.writerow([os.path.basename(item.get("path", "N/A")),
                                     item.get("hash", "N/A"),
                                     item.get("source_ip", "N/A"),
                                     item.get("dest_ip", "N/A"),
                                     vt_pos, vt_tot])
                writer.writerow([])
                writer.writerow(["Malware Detected"])
                writer.writerow(["IP", "Malware", "Count"])
                for item in report_data.get("malware_detected", []):
                    writer.writerow([item.get("ip", "N/A"),
                                     item.get("malware", "N/A"),
                                     item.get("count", "N/A")])
                writer.writerow([])
                writer.writerow(["Top Active IPs"])
                writer.writerow(["IP", "Packets", "Protocols", "Location"])
                for item in report_data.get("top_active_ips", []):
                    proto_str = ", ".join([f"{k}: {v}" for k, v in item.get("protocols", {}).items()])
                    writer.writerow([item.get("ip", "N/A"),
                                     item.get("packets", "N/A"),
                                     proto_str,
                                     item.get("location", "N/A")])
                writer.writerow([])
                writer.writerow(["Protocol Usage"])
                writer.writerow(["Protocol", "Packets"])
                for proto, count in report_data.get("protocol_usage", {}).items():
                    writer.writerow([proto, count])
                writer.writerow([])
                writer.writerow(["Recommendations"])
                for rec in report_data.get("recommendations", []):
                    writer.writerow([rec])
            if logger:
                logger.info(f"CSV report saved: {file_path}")
        except Exception as e:
            if logger:
                logger.exception(f"CSV save error: {str(e)}")
            raise

    @staticmethod
    @profile
    def save_txt(file_path, report_text, report_data, logger):
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(report_text)
            if logger:
                logger.info(f"TXT report saved: {file_path}")
        except Exception as e:
            if logger:
                logger.exception(f"TXT save error: {str(e)}")
            raise

    @staticmethod
    @profile
    def save_html(file_path, report_text, report_data, logger):
        asyncio.run(ReportSaver.async_save_html(file_path, report_text, report_data, logger))

    @staticmethod
    async def async_save_html(file_path, report_text, report_data, logger):
        processed_report_data = preprocess_report_data(report_data)
        total_threats = processed_report_data.get("key_findings", {}).get("total_threats", "N/A")
        import json
        proto_labels = list(processed_report_data.get("protocol_usage", {"TCP": 99022, "UDP": 1368, "ICMP": 2}).keys())
        proto_values = list(processed_report_data.get("protocol_usage", {"TCP": 99022, "UDP": 1368, "ICMP": 2}).values())
        top_ips_data = processed_report_data.get("top_active_ips", [
            {"ip": "10.90.90.116", "packets": 96126},
            {"ip": "89.232.113.1", "packets": 56981},
            {"ip": "85.140.1.102", "packets": 37162},
            {"ip": "151.101.244.204", "packets": 4383},
            {"ip": "172.18.0.2", "packets": 2946}
        ])
        top_ips = [item["ip"] for item in top_ips_data][:5]
        top_ip_packets = [item["packets"] for item in top_ips_data][:5]
        peak_data = processed_report_data.get("peak_activity", [
            {"time": "2019-05-22 18:42", "total": 15090},
            {"time": "2019-05-22 18:41", "total": 14603},
            {"time": "2019-05-22 18:43", "total": 11926},
            {"time": "2019-05-22 18:15", "total": 7164},
            {"time": "2019-05-22 18:16", "total": 6959}
        ])
        peak_times = [item["time"] for item in peak_data][:5]
        peak_totals = [item["total"] for item in peak_data][:5]
        attack_timeline = processed_report_data.get("attack_timeline", {"times": [], "ips": [], "matrix": []})
        if not isinstance(attack_timeline, dict):
            attack_timeline = {"times": [], "ips": [], "matrix": []}

        logger.debug(f"Protocol data: labels={proto_labels}, values={proto_values}")
        logger.debug(f"Top IPs: labels={top_ips}, values={top_ip_packets}")
        logger.debug(f"Peak activity: times={peak_times}, totals={peak_totals}")
        logger.debug(f"Attack timeline: {attack_timeline}")

        def make_extracted_file_row(item):
            vt = item.get("vt_result")
            if not vt:
                vt_str = "Не проверено"
            else:
                vt_str = f"{vt.get('positives', 'N/A')}/{vt.get('total', 'N/A')}"
            return (f"<tr><td>{os.path.basename(item.get('path', 'N/A'))}</td>"
                    f"<td>{item.get('hash', 'N/A')[:8]}...</td>"
                    f"<td>{item.get('source_ip', 'N/A')}</td>"
                    f"<td>{item.get('dest_ip', 'N/A')}</td>"
                    f"<td>{vt_str}</td></tr>")
        extracted_rows = ''.join(make_extracted_file_row(item) for item in processed_report_data.get("extracted_files", []))
        html_content = f"""
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>PCAP Analysis Report</title>
    <link rel="stylesheet" type="text/css" href="https://cdn.datatables.net/1.13.4/css/jquery.dataTables.min.css">
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.4/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.plot.ly/plotly-2.35.2.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js"></script>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2 {{ color: #333; }}
        .summary {{ background: #f0f0f0; padding: 10px; margin-bottom: 20px; }}
        .threat {{ color: red; }}
        pre {{ background: #f5f5f5; padding: 10px; border-radius: 5px; white-space: pre-wrap; }}
        table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background: #f2f2f2; }}
        .chart-container {{ margin-top: 20px; width: 100%; max-width: 600px; height: 400px; }}
        canvas, #heatmap {{ width: 100% !important; height: 100% !important; }}
    </style>
</head>
<body>
    <h1>PCAP Analysis Report</h1>
    <div class="summary">
        <h2>Ключевые выводы</h2>
        <ul>
            <li>Обработано {processed_report_data.get("total_packets", "N/A")} пакетов за {processed_report_data.get("duration", "N/A")}.</li>
            <li>Основной источник трафика: {top_ips[0] if top_ips else "N/A"} ({top_ip_packets[0] if top_ip_packets else "N/A"} пакетов).</li>
            <li>Всего угроз: {total_threats}.</li>
        </ul>
    </div>
    <pre>{html.escape(report_text)}</pre>
    <h2>Подозрительные IP</h2>
    <table id="suspicious_ips_table">
        <thead>
            <tr><th>IP</th><th>Причины</th><th>Локация</th></tr>
        </thead>
        <tbody>
            {''.join(f"<tr><td>{item.get('ip', 'N/A')}</td><td>{', '.join(item.get('reasons', []))}</td><td>{item.get('location', 'N/A')}</td></tr>" for item in processed_report_data.get("suspicious_ips", []))}
        </tbody>
    </table>
    <h2>Извлечённые файлы</h2>
    <table id="extracted_files_table">
        <thead>
            <tr><th>Файл</th><th>SHA256</th><th>Источник</th><th>Назначение</th><th>VirusTotal</th></tr>
        </thead>
        <tbody>
            {extracted_rows}
        </tbody>
    </table>
    <h2>Использование протоколов</h2>
    <div class="chart-container">
        <canvas id="protocol_chart"></canvas>
    </div>
    <h2>Пиковая активность</h2>
    <div class="chart-container" id="peak_activity_chart"></div>
    <h2>Рекомендации</h2>
    <ul>
        {''.join(f"<li>{rec}</li>" for rec in processed_report_data.get("recommendations", []))}
    </ul>
    <h2>Тепловая карта активности</h2>
    <div class="chart-container">
        <div id="heatmap"></div>
    </div>
    <script>
      $(document).ready(function() {{
          $('#suspicious_ips_table').DataTable({{
              "paging": true,
              "searching": true
          }});
          $('#extracted_files_table').DataTable({{
              "paging": true,
              "searching": true
          }});
      }});
    </script>
    <script>
        const protoCtx = document.getElementById('protocol_chart').getContext('2d');
        new Chart(protoCtx, {{
            type: 'pie',
            data: {{
                labels: {json.dumps(proto_labels)},
                datasets: [{{ data: {json.dumps(proto_values)}, backgroundColor: ['#36A2EB', '#FFCE56', '#FF6384'] }}]
            }},
            options: {{ 
                responsive: true, 
                maintainAspectRatio: false,
                plugins: {{ legend: {{ position: 'top' }} }}
            }}
        }});
        const peakData = {{
            x: {json.dumps(peak_times)},
            y: {json.dumps(peak_totals)},
            type: 'scatter',
            mode: 'lines+markers',
            name: 'Packets',
            line: {{ color: '#36A2EB' }}
        }};
        const peakLayout = {{
            title: 'Peak Activity Over Time',
            xaxis: {{ title: 'Время', tickangle: -45 }},
            yaxis: {{ title: 'Пакеты' }},
            height: 400,
            width: 600,
            margin: {{ t: 50, b: 100, l: 50, r: 50 }}
        }};
        Plotly.newPlot('peak_activity_chart', [peakData], peakLayout);
        var heatmapData = [ {{
            z: {json.dumps(attack_timeline.get("matrix", []))},
            x: {json.dumps(attack_timeline.get("times", []))},
            y: {json.dumps(attack_timeline.get("ips", []))},
            type: 'heatmap',
            colorscale: 'Viridis'
        }} ];
        var heatmapLayout = {{
            title: 'Активность IP по времени',
            xaxis: {{ title: 'Время' }},
            yaxis: {{ title: 'IP адрес' }}
        }};
        Plotly.newPlot('heatmap', heatmapData, heatmapLayout);
    </script>
</body>
</html>
"""
        minified_html = htmlmin.minify(html_content, remove_empty_space=True)
        try:
            async with aiofiles.open(file_path, "w", encoding="utf-8") as f:
                await f.write(minified_html)
            logger.info(f"HTML report saved: {file_path}")
        except Exception as e:
            logger.exception(f"HTML save error: {str(e)}")
            raise
