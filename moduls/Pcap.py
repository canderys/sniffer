import struct
import time
from moduls.NetworkSniffer import NetworkSniffer


PCAP_GLOBAL_HEADER_FMT = '@ I H H i I I I '


# Global Header Values
PCAP_MAGICAL_NUMBER = 2712847316
PCAP_MJ_VERN_NUMBER = 2
PCAP_MI_VERN_NUMBER = 4
PCAP_LOCAL_CORECTIN = 0
PCAP_ACCUR_TIMSTAMP = 0
PCAP_MAX_LENGTH_CAP = 65535
PCAP_DATA_LINK_TYPE = 1


#     Pcap Global Header Format :
#                       ( magic number +
#                         major version number +
#                         minor version number +
#                         GMT to local correction +
#                         accuracy of timestamps +
#                         max length of captured #packets, in octets +
#                         data link type)


class Pcap:

    def __init__(self, buffer, mode, link_type=PCAP_DATA_LINK_TYPE):
        self.link_type = link_type
        self.buffer = buffer
        self.mode = mode
        if mode == "w":
            self.buffer.write(struct.pack(PCAP_GLOBAL_HEADER_FMT,
                                          PCAP_MAGICAL_NUMBER,
                                          PCAP_MJ_VERN_NUMBER,
                                          PCAP_MI_VERN_NUMBER,
                                          PCAP_LOCAL_CORECTIN,
                                          PCAP_ACCUR_TIMSTAMP,
                                          PCAP_MAX_LENGTH_CAP,
                                          self.link_type))

    def write(self, data):
        if self.mode != "w":
            raise ValueError("incorrect mode")
        ts_sec, ts_usec = map(int, str(time.time()).split('.'))
        length = len(data)
        self.buffer.write(struct.pack(
            '@ I I I I', ts_sec, ts_usec, length, length))
        self.buffer.write(data)
        self.buffer.flush()

    def get_packets_from_pcap(self):
        if self.mode != "r":
            raise ValueError("incorrect mode")
        header = self.buffer.read(24)
        timestamps = self.buffer.read(16)
        sniffer = NetworkSniffer()
        while timestamps:
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
                '@ I I I I', timestamps)
            data = self.buffer.read(incl_len)
            parsed_packet = sniffer.parse_packet(data)
            if parsed_packet:
                yield parsed_packet
            timestamps = self.buffer.read(16)
