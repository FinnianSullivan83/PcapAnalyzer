# PCAP Analyzer v3.1

Инструмент для локального анализа сетевого трафика (PCAP-файлов) с интерфейсом GUI и CLI. Поддерживает извлечение подозрительных пакетов, сигнатурный анализ, генерацию отчётов и экспорт в форматы HTML, PDF, CSV, JSON и CEF (для SIEM-систем).

## 🚀 Быстрый старт

### 📦 Установка зависимостей

pip install -r requirements.txt

🖥 Запуск графического интерфейса (GUI)

python -m pcap_analyzer.gui.main

🛠 Запуск через командную строку (CLI)

python -m pcap_analyzer.cli.cli --file path/to/input.pcap --output path/to/report.json

Дополнительные параметры:

--format Формат отчёта: json, html, pdf, csv, txt

--cef Экспорт в формате CEF (для JSON)

--no-vt Отключить проверку VirusTotal

⚙️ Конфигурация
Настраивается в config.ini:

[DEFAULT]
vt_api_key = encrypted:...
extracted_files_dir = extracted_files
ip_threshold = 1000
port_threshold = 500
language = ru

🔐 VirusTotal (опционально)
Для проверки извлечённых файлов необходим API-ключ VT. Задается в config.ini или отключается через --no-vt.

🧪 Тестирование

python -m unittest discover -s tests

📬 Обратная связь
Pull requests и предложения приветствуются!


#### pcap_analyzer/requirements.txt
```plaintext
aiofiles==24.1.0
htmlmin==0.1.12
matplotlib==3.6.3
scapy==2.5.0
geoip2==4.7.0
reportlab==3.6.12
cryptography==41.0.0


pip uninstall -y numpy
pip install "numpy<2.0"

pip uninstall -y matplotlib
pip install matplotlib
