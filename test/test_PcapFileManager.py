import unittest
import tempfile
import os
from moduls.sniffer_core import PcapFileManager, Pcap


class TestPcapFileManager(unittest.TestCase):
    def setUp(self):
        self.delete_list = []

    def test_count(self):
        path = os.path.join(".", "test", "saved_packets", "saved_packets.pcap")
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            with open(path, "rb") as data:
                pcap = Pcap()
                packets = pcap.get_packets_from_pcap(data)
                flags = {"name": tmp.name, "filepackets": 10}
                pcap_manager = PcapFileManager(flags)
                for packet in packets:
                    pcap_manager.write(packet.data)
        pcap_manager.close()
        for file in pcap_manager.files:
            with open(file, "rb") as pcap_file:
                packets = pcap.get_packets_from_pcap(pcap_file)
                for (idx, _) in enumerate(packets):
                    pass
                self.assertLess(idx, 11)
        self.delete_list = pcap_manager.files

    def tearDown(self):
        for file in self.delete_list:
            if os.path.exists(file):
                os.remove(file)
