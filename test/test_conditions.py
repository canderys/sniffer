import unittest
import tempfile
import os
import math
from sniffer import run
from moduls.sniffer_core.Headers import TCP, ICMP, UDP
from moduls.sniffer_core import NetworkSniffer, Pcap


class TestConditions(unittest.TestCase):

    def test_tcp_condition(self):
        self.run_condition('proto == tcp', self.tcp_condition)

    def test_complex_condition(self):
        condition = "(src.port == 443 and proto == udp)"\
            "or (dst.port == 40988 and proto == tcp)"
        self.run_condition(condition, self.complex_condition)

    def setUp(self):
        self.delete_list = []

    def run_condition(self, condition, boolFunc):
        with tempfile.NamedTemporaryFile(dir=".", delete=False) as temp:
            self.name = "." + os.path.basename(temp.name)
            self.delete_list.append(self.name)
            self.path = "./test/saved_packets/saved_packets.pcap"
            run(['-r', self.path, '-c', condition, 'pcap', '-n', self.name])
        with open(self.name, "rb") as tmp:
            pcap = Pcap()
            for packet in NetworkSniffer(pcap.get_packets_from_pcap(tmp)). \
                    get_packets(math.inf):
                self.assertEqual(True, boolFunc(packet[0]))

    def tcp_condition(self, packet):
        return isinstance(packet.application_layer, TCP)

    def complex_condition(self, packet):
        first = packet.src_port == 443 and isinstance(
            packet.application_layer, UDP)
        second = packet.dest_port == 40988 and isinstance(
            packet.application_layer, TCP)
        return first or second

    def tearDown(self):
        for file in self.delete_list:
            os.remove(file[1:])
            os.remove(file)
