import tkinter as tk
from pcap_analyzer.gui.pcap_analyzer_app import PcapAnalyzerApp
from pcap_analyzer.utils.config_manager import load_config
import matplotlib.pyplot as plt

if __name__ == "__main__":
    config = load_config()
    root = tk.Tk()
    app = PcapAnalyzerApp(root, config)
    try:
        root.mainloop()
    finally:
        plt.close('all')
