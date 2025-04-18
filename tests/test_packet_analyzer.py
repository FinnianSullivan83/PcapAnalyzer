import unittest
from analyzer.packet_analyzer import PacketAnalyzer
from analyzer.analysis_result import AnalysisResult
import os
import configparser

class TestPacketAnalyzer(unittest.TestCase):
    def setUp(self):
        self.config = configparser.ConfigParser()
        self.config.read('config.ini')
        self.pcap_file = "test.pcap"  # Требуется тестовый файл
        self.extracted_files_dir = "test_extracted_files"
        self.vt_api_key = self.config['DEFAULT'].get('vt_api_key', '')
        self.analyzer = PacketAnalyzer(self.pcap_file, self.extracted_files_dir, self.vt_api_key, False, lambda x: print(x), self.config)

    def test_count_packets(self):
        self.analyzer.count_packets()
        self.assertGreater(self.analyzer.total_packets, 0)

    def test_analyze_packets(self):
        result = self.analyzer.analyze_packets(lambda analyzed, total: None)
        self.assertIsInstance(result, AnalysisResult)
        self.assertTrue(len(result.ip_counter) > 0)

    def test_geoip_cache(self):
        location = self.analyzer.get_geoip_location("8.8.8.8")
        self.assertIn("United States", location)

    def tearDown(self):
        if os.path.exists(self.extracted_files_dir):
            for file in os.listdir(self.extracted_files_dir):
                os.remove(os.path.join(self.extracted_files_dir, file))
            os.rmdir(self.extracted_files_dir)

if __name__ == '__main__':
    unittest.main()
