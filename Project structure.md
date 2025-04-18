project_root/
├── pcap_analyzer/
│   ├── analyzer/
│   │   ├── __init__.py
│   │   ├── packet_analyzer.py           # Логика анализа трафика, включая метод analyze_packets с доработками
│   │   ├── analysis_result.py           # Класс для хранения результатов анализа
│   │   └── signature_manager.py         # Управление сигнатурами атак
│   ├── cli/
│   │   ├── __init__.py
│   │   └── cli.py                       # CLI-интерфейс для запуска анализа и экспорта отчёта
│   ├── gui/
│   │   ├── __init__.py
│   │   ├── pcap_analyzer_app.py         # Графический интерфейс приложения с фильтрацией логов
│   │   └── main.py                      # Точка входа для GUI, загружающая конфигурацию через utils
│   ├── reporting/
│   │   ├── __init__.py
│   │   ├── report_generator.py          # Генерация отчётов
│   │   ├── report_saver.py              # Сохранение отчётов (PDF, HTML, TXT, CSV, JSON)
│   │   ├── report_preprocessor.py       # Предобработка данных отчёта (удаление дубликатов, сортировка)
│   │   └── html_blocks.py               # HTML-блоки для встроенной визуализации отчёта
│   └── utils/
│       ├── __init__.py
│       ├── config_manager.py            # Централизованная загрузка и обработка config.ini (с дешифровкой ключей)
│       ├── encryption.py                # Функция дешифрования API-ключа
│       └── logger.py                    # Централизованная настройка логирования (file/console)
├── tests/
│   └── test_packet_analyzer.py          # Модульные тесты для PacketAnalyzer и связанных компонентов
├── resources/
│   ├── malware_signatures.json          # Сигнатуры вредоносных шаблонов для анализа
│   ├── GeoLite2-City.mmdb               # База данных GeoIP для определения локаций IP
│   └── DejaVuSans.ttf                   # Шрифт для формирования PDF-отчетов
├── config.ini                           # Файл конфигурации проекта
├── README.md                            # Документация, описание установки и запуска проекта
└── requirements.txt                     # Файл со списком зависимостей
