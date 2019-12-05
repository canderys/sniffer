import unittest
import socket
from moduls.Rawsniffer import Rawsniffer


class TestRawsniffer(unittest.TestCase):

    def test_TCP_parse(self):
        test_file = open("test/tcp_packet", "rb")
        data = test_file.read()
        test_file.close()
        raw_shiffer = Rawsniffer()
        sniffed_data = raw_shiffer.get_sniffed_data(data)
        self.assertEqual(raw_shiffer.dest_mac, 'AC:FD:CE:C7:28:1F')
        self.assertEqual(raw_shiffer.src_port_tcp, 44285)


if __name__ == '__main__':
    unittest.main()
