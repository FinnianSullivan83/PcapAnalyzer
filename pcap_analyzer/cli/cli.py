import argparse
import datetime
from analyzer.packet_analyzer import PacketAnalyzer
from reporting.report_generator import ReportGenerator
from reporting.report_saver import ReportSaver
from utils.config_manager import load_config

def main():
    parser = argparse.ArgumentParser(
        description="""\
Анализатор сетевого трафика PCAP-файлов с сохранением отчета в различных форматах.
Примеры использования:
  python cli.py --file input.pcap --output report.json
  python cli.py --file input.pcap --output report.json --format json --cef
  python cli.py --file input.pcap --output report.txt --format txt
""",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('--file', required=True, help='Путь к PCAP-файлу')
    parser.add_argument('--output', required=True, help='Файл для сохранения отчета')
    parser.add_argument('--format', default='json', choices=['json', 'txt', 'html', 'pdf', 'csv'], help='Формат отчета')
    parser.add_argument('--cef', action='store_true', help='Экспорт в формате CEF (для JSON)')
    parser.add_argument('--no-vt', action='store_true', help='Отключить VirusTotal')
    args = parser.parse_args()

    config = load_config()

    analyzer = PacketAnalyzer(
        args.file,
        config['DEFAULT']['extracted_files_dir'],
        config['DEFAULT']['vt_api_key'],
        not args.no_vt,
        lambda m, level='INFO': print(m),
        config
    )

    analyzer.count_packets()
    start_time = datetime.datetime.now()
    result = analyzer.analyze_packets(lambda a, b: None)
    end_time = datetime.datetime.now()

    generator = ReportGenerator(
        args.file, start_time, end_time, analyzer.total_packets,
        int(config['DEFAULT']['ip_threshold']), int(config['DEFAULT']['port_threshold'])
    )
    report_text, report_data = generator.generate(result)

    if args.format.lower() == 'json' and args.cef:
        ReportSaver.save_json(args.output, report_text, report_data, logger=None, cef=True)
    else:
        ReportSaver.save(args.format.upper(), args.output, report_text, report_data, logger=None)

if __name__ == '__main__':
    main()
