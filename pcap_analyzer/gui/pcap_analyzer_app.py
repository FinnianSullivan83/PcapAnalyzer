# pcap_analyzer/gui/pcap_analyzer_app.py

import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk, simpledialog
import threading
import logging
import asyncio
from pcap_analyzer.analyzer.packet_analyzer import PacketAnalyzer
from pcap_analyzer.reporting.report_generator import ReportGenerator
from pcap_analyzer.reporting.report_saver import ReportSaver
from pcap_analyzer.utils.logger import setup_logger
import os
import datetime
import matplotlib
matplotlib.use('TkAgg')
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from pcap_analyzer.utils.logger import setup_logger  # Импорт централизованного логгера

class PcapAnalyzerApp:
    def __init__(self, root, config):
        self.root = root
        self.config = config
        self.root.title("PCAP Analyzer - Enhanced")
        self.root.geometry("1200x900")
        self.pcap_file = None
        self.start_time = None
        self.end_time = None
        self.final_result = ""
        self.report_data = {}
        self.running = False
        self.counting = False
        self.theme = "light"
        self.language = config['DEFAULT']['language']
        self.extracted_files_dir = config['DEFAULT']['extracted_files_dir']
        self.vt_api_key = config['DEFAULT']['vt_api_key']
        self.use_vt = tk.BooleanVar(value=False)
        self.filter_var = tk.BooleanVar(value=False)
        self.filter_keyword = tk.StringVar(value="")
        self.ip_threshold_var = tk.IntVar(value=int(config['DEFAULT']['ip_threshold']))
        self.port_threshold_var = tk.IntVar(value=int(config['DEFAULT']['port_threshold']))
        self.max_workers_var = tk.IntVar(value=int(config['DEFAULT']['max_workers']))
        self.canvas = None
        self.setup_logging()
        self.setup_ui()
        if not os.path.exists(self.extracted_files_dir):
            os.makedirs(self.extracted_files_dir)
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def setup_logging(self):
        log_file = self.config['DEFAULT'].get('log_file', 'pcap_analyzer.log')
        self.logger = setup_logger("PcapAnalyzer", log_file)

    def setup_ui(self):
        self.style = ttk.Style()
        self.style.theme_use("clam")
        button_frame = ttk.Frame(self.root)
        button_frame.pack(pady=5)
        ttk.Button(button_frame, text="Выбрать PCAP-файл" if self.language == "ru" else "Select PCAP File", 
                   command=self.select_pcap).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Начать анализ" if self.language == "ru" else "Start Analysis", 
                   command=self.start_analysis).pack(side=tk.LEFT, padx=5)
        self.stop_button = ttk.Button(button_frame, text="Остановить анализ" if self.language == "ru" else "Stop Analysis", 
                                        command=self.stop_analysis, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        self.cancel_count_button = ttk.Button(button_frame, text="Отменить подсчет" if self.language == "ru" else "Cancel Counting", 
                                                command=self.cancel_counting, state=tk.DISABLED)
        self.cancel_count_button.pack(side=tk.LEFT, padx=5)
        self.save_button = ttk.Button(button_frame, text="Сохранить отчет" if self.language == "ru" else "Save Report", 
                                      command=self.save_report_dialog, state=tk.DISABLED)
        self.save_button.pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Перепроверить файлы VT", command=self.recheck_virustotal).pack(side=tk.LEFT, padx=5)
        self.progress = ttk.Progressbar(self.root, maximum=100, length=300, mode='determinate')
        self.progress.pack(pady=5)
        self.progress_label = tk.Label(self.root, text="Прогресс: 0% (0/0)")
        self.progress_label.pack(pady=5)
        self.status_label = tk.Label(self.root, text="")
        self.status_label.pack(pady=5)
        config_frame = ttk.LabelFrame(self.root, text="Настройки" if self.language == "ru" else "Settings")
        config_frame.pack(pady=5, fill="x")
        tk.Checkbutton(config_frame, text="Показать только подозрительные IP" if self.language == "ru" else "Show Suspicious IPs Only", 
                       variable=self.filter_var, command=self.apply_filter).pack(pady=2)
        tk.Checkbutton(config_frame, text="Использовать VirusTotal" if self.language == "ru" else "Use VirusTotal", 
                       variable=self.use_vt).pack(pady=2)
        ttk.Label(config_frame, text="Фильтр логов:" if self.language == "ru" else "Log Filter:").pack(pady=2)
        entry = ttk.Entry(config_frame, textvariable=self.filter_keyword)
        entry.pack(pady=2)
        entry.bind("<KeyRelease>", lambda event: self.apply_filter())
        ttk.Label(config_frame, text="Порог активности IP:" if self.language == "ru" else "IP Threshold:").pack(pady=2)
        ttk.Entry(config_frame, textvariable=self.ip_threshold_var).pack(pady=2)
        ttk.Label(config_frame, text="Порог активности портов:" if self.language == "ru" else "Port Threshold:").pack(pady=2)
        ttk.Entry(config_frame, textvariable=self.port_threshold_var).pack(pady=2)
        ttk.Label(config_frame, text="Количество потоков:" if self.language == "ru" else "Max Workers:").pack(pady=2)
        ttk.Entry(config_frame, textvariable=self.max_workers_var).pack(pady=2)
        ttk.Button(self.root, text="Переключить тему" if self.language == "ru" else "Toggle Theme", 
                   command=self.toggle_theme).pack(pady=5)
        ttk.Button(self.root, text="Сменить язык" if self.language == "ru" else "Switch Language", 
                   command=self.toggle_language).pack(pady=5)
        main_frame = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        main_frame.pack(fill="both", expand=True, pady=5)
        left_frame = ttk.Frame(main_frame)
        main_frame.add(left_frame, weight=1)
        self.log_text = tk.scrolledtext.ScrolledText(left_frame, width=50, height=20)
        self.log_text.pack(fill="both", expand=True, pady=5)
        self.attack_tree = ttk.Treeview(left_frame, columns=("IP", "Type", "Packet", "Timestamp", "Payload"), show="headings", height=10)
        self.attack_tree.heading("IP", text="IP")
        self.attack_tree.heading("Type", text="Тип атаки")
        self.attack_tree.heading("Packet", text="Пакет #")
        self.attack_tree.heading("Timestamp", text="Время")
        self.attack_tree.heading("Payload", text="Payload")
        self.attack_tree.column("IP", width=100)
        self.attack_tree.column("Type", width=100)
        self.attack_tree.column("Packet", width=70)
        self.attack_tree.column("Timestamp", width=150)
        self.attack_tree.column("Payload", width=200)
        self.attack_tree.pack(fill="x", pady=5)
        self.attack_tree.bind("<Double-1>", self.show_attack_details)
        right_frame = ttk.Frame(main_frame)
        main_frame.add(right_frame, weight=1)
        self.graph_frame = ttk.Frame(right_frame)
        self.graph_frame.pack(fill="both", expand=True)
        self.logs = []

    def select_pcap(self):
        self.pcap_file = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap *.pcapng"), ("All files", "*.*")])
        if self.pcap_file:
            self.log_message(f"Выбран файл: {self.pcap_file}")
            self.count_packets()

    def count_packets(self):
        if not self.pcap_file:
            return
        self.counting = True
        self.cancel_count_button.config(state=tk.NORMAL)
        self.update_status("Подсчет пакетов...")
        threading.Thread(target=self.run_packet_count, daemon=True).start()

    def run_packet_count(self):
        analyzer = PacketAnalyzer(self.pcap_file, self.extracted_files_dir, self.vt_api_key, self.use_vt.get(), self.log_message, self.config)
        analyzer.count_packets()
        self.counting = False
        self.cancel_count_button.config(state=tk.DISABLED)
        self.update_status("Подсчет завершен")

    def cancel_counting(self):
        self.counting = False
        self.update_status("Подсчет отменен")

    def start_analysis(self):
        if not self.pcap_file:
            messagebox.showwarning("Ошибка", "Сначала выберите PCAP-файл!")
            return
        self.running = True
        self.start_time = datetime.datetime.now()
        self.stop_button.config(state=tk.NORMAL)
        self.save_button.config(state=tk.DISABLED)
        self.update_status("Анализ начат...")
        threading.Thread(target=self.run_analysis, daemon=True).start()

    def stop_analysis(self):
        self.running = False
        self.update_status("Остановка анализа...")

    def run_analysis(self):
        try:
            analyzer = PacketAnalyzer(self.pcap_file, self.extracted_files_dir, self.vt_api_key, self.use_vt.get(), self.log_message, self.config)
            result = analyzer.analyze_packets(self.update_progress)
            if self.running:
                self.end_time = datetime.datetime.now()
                generator = ReportGenerator(self.pcap_file, self.start_time, self.end_time, analyzer.total_packets,
                                            self.ip_threshold_var.get(), self.port_threshold_var.get())
                self.final_result, self.report_data = generator.generate(result)
                self.log_message(self.final_result)
                self.save_button.config(state=tk.NORMAL)
                self.stop_button.config(state=tk.DISABLED)
                self.update_progress(analyzer.total_packets, analyzer.total_packets)
                self.update_status("Анализ завершён")
                self.root.after(0, self.plot_graph)
                self.root.after(0, self.update_attack_tree)
            else:
                self.end_time = datetime.datetime.now()
                self.update_status("Анализ остановлен")
        except Exception as e:
            self.log_message(f"Ошибка: {str(e)}")
            self.logger.error(f"Analysis error: {str(e)}")
            self.end_time = datetime.datetime.now()
            self.stop_button.config(state=tk.DISABLED)
            self.save_button.config(state=tk.NORMAL)
            self.update_status("Ошибка анализа")

    def update_progress(self, current, total):
        if total > 0:
            percentage = (current / total) * 100
            self.progress['value'] = percentage
            self.progress_label.config(text=f"Прогресс: {percentage:.1f}% ({current}/{total})")
            self.root.update_idletasks()

    def update_status(self, message):
        self.status_label.config(text=message)
        self.root.update_idletasks()

    def log_message(self, message, level="INFO"):
        if level == "DEBUG":
            self.logger.debug(message)
        else:
            self.logs.append(message)
            self.apply_filter()
            self.logger.info(message)

    def apply_filter(self):
        # Убедимся, что self.logs существует
        if not hasattr(self, 'logs'):
            self.logs = []
        # Очистка виджета логов
        self.log_text.delete(1.0, tk.END)
        
        keyword = self.filter_keyword.get().lower()
        show_suspicious_only = self.filter_var.get()
        # Отладочный вывод текущих параметров фильтра
        self.logger.debug(f"apply_filter: keyword='{keyword}', show_suspicious_only={show_suspicious_only}")
        
        SUSPICIOUS_KEYWORDS = [
            "подозр", "ssh", "brute", "sql", "xss", "вредонос",
            "malware", "угроз", "атак", "инъекц", "virus"
        ]
        
        for line in self.logs:
            line_lower = line.lower()
            # Фильтрация по ключевому слову (если задано)
            match_keyword = (keyword in line_lower) if keyword else True
            # Проверка, что строка содержит хотя бы одно подозрительное слово
            match_suspicious = any(kw in line_lower for kw in SUSPICIOUS_KEYWORDS)
            
            # Если выбран режим "только подозрительные IP" и строка не содержит подозрительного слова, пропускаем
            if show_suspicious_only and not match_suspicious:
                continue
            if match_keyword:
                self.log_text.insert(tk.END, line + "\n")
        self.log_text.see(tk.END)


    def save_report_dialog(self):
        filetypes = [
            ("Text files", "*.txt"),
            ("HTML files", "*.html"),
            ("PDF files", "*.pdf"),
            ("CSV files", "*.csv"),
            ("JSON files", "*.json")
        ]
        filename = filedialog.asksaveasfilename(filetypes=filetypes, initialfile="report")
        if filename:
            saver = ReportSaver()
            extension = os.path.splitext(filename)[1].lower()
            format_map = {
                ".txt": "TXT",
                ".html": "HTML",
                ".pdf": "PDF",
                ".csv": "CSV",
                ".json": "JSON"
            }
            if not extension:
                format_type = simpledialog.askstring("Выбор формата", "Укажите формат (txt, html, pdf, csv, json):", parent=self.root)
                if format_type:
                    format_type = format_type.lower()
                    extension = f".{format_type}"
                    filename += extension
                    format_type = format_map.get(extension, "TXT")
                else:
                    format_type = "TXT"
                    filename += ".txt"
            else:
                format_type = format_map.get(extension, "TXT")
            self.log_message(f"DEBUG: Имя файла: {filename}", level="DEBUG")
            self.log_message(f"DEBUG: Извлеченное расширение: {extension}", level="DEBUG")
            self.log_message(f"DEBUG: Выбранный формат: {format_type}", level="DEBUG")
            try:
                saver.save(format_type, filename, self.final_result, self.report_data, self.logger)
                self.log_message(f"Отчет сохранен: {filename}")
            except Exception as e:
                self.log_message(f"Ошибка сохранения отчета: {str(e)}")
                self.logger.error(f"Save report error: {str(e)}")

    def toggle_theme(self):
        self.theme = "dark" if self.theme == "light" else "light"
        bg = "#2e2e2e" if self.theme == "dark" else "#ffffff"
        fg = "#ffffff" if self.theme == "dark" else "#000000"
        self.root.configure(bg=bg)
        self.log_text.configure(bg=bg, fg=fg)
        self.progress_label.configure(bg=bg, fg=fg)
        self.status_label.configure(bg=bg, fg=fg)

    def toggle_language(self):
        self.language = "en" if self.language == "ru" else "ru"
        self.config['DEFAULT']['language'] = self.language
        with open('config.ini', 'w') as configfile:
            self.config.write(configfile)
        messagebox.showinfo("Перезапуск", "Пожалуйста, перезапустите приложение для смены языка.")

    def plot_graph(self):
        if self.report_data.get("protocol_usage"):
            if self.canvas:
                self.canvas.get_tk_widget().destroy()
                plt.close(self.canvas.figure)
            fig, ax = plt.subplots(figsize=(5, 5))
            labels = list(self.report_data["protocol_usage"].keys())
            sizes = list(self.report_data["protocol_usage"].values())
            ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
            ax.set_title("Protocol Distribution")
            self.canvas = FigureCanvasTkAgg(fig, master=self.graph_frame)
            self.canvas.draw()
            self.canvas.get_tk_widget().pack(fill="both", expand=True)

    def update_attack_tree(self):
        for item in self.attack_tree.get_children():
            self.attack_tree.delete(item)
        for threat in ["xss_attacks", "sql_injections", "cmd_injections", "dir_traversals"]:
            for entry in self.report_data.get(threat, []):
                ip = entry["ip"]
                for attack in entry["attacks"]:
                    self.attack_tree.insert("", "end", values=(ip, threat.replace("_", " ").title(), 
                                                              attack["packet_num"], attack["timestamp"], attack["payload"]))

    def show_attack_details(self, event):
        item = self.attack_tree.selection()[0]
        values = self.attack_tree.item(item, "values")
        ip, attack_type, packet_num, timestamp, payload = values
        details = f"IP: {ip}\nТип атаки: {attack_type}\nПакет #: {packet_num}\nВремя: {timestamp}\nPayload: {payload}\nWireshark фильтр: frame.number == {packet_num}"
        messagebox.showinfo("Детали атаки", details)

    def recheck_virustotal(self):
        if not self.report_data.get("extracted_files"):
            self.log_message("Нет файлов для перепроверки VirusTotal.")
            return
        self.log_message("Запуск повторной проверки файлов в VirusTotal...")
        try:
            from pcap_analyzer.analyzer.packet_analyzer import PacketAnalyzer
        except ImportError:
            self.log_message("Ошибка импорта PacketAnalyzer.")
            return
        analyzer = PacketAnalyzer(self.pcap_file, self.extracted_files_dir, self.vt_api_key, self.use_vt.get(), self.log_message, self.config)
        file_hashes = [file_info.get("hash") for file_info in self.report_data.get("extracted_files", []) if file_info.get("hash")]
        if not file_hashes:
            self.log_message("Нет валидных хэшей для проверки.")
            return
        try:
            vt_results = asyncio.run(analyzer.check_virustotal_batch(file_hashes))
        except Exception as e:
            self.log_message(f"Ошибка проверки VirusTotal: {str(e)}")
            return
        for i, result in enumerate(vt_results):
            if i < len(self.report_data["extracted_files"]):
                self.report_data["extracted_files"][i]["vt_result"] = result
        self.log_message("VirusTotal перепроверка завершена, отчет обновлен.")

    def on_closing(self):
        if self.running or self.counting:
            self.running = False
            self.counting = False
            self.update_status("Остановка...")
            self.root.after(100, self.on_closing)
            return
        self.root.destroy()
