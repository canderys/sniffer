import struct
import time
import os
from moduls.sniffer_core.exceptions import ParsingArgsError
from moduls.sniffer_core.NetworkSniffer import PacketInfo


PCAP_GLOBAL_HEADER_FMT = '@ I H H i I I I '


# Global Header Values
PCAP_MAGICAL_NUMBER = 2712847316
PCAP_MJ_VERN_NUMBER = 2
PCAP_MI_VERN_NUMBER = 4
PCAP_LOCAL_CORECTIN = 0
PCAP_ACCUR_TIMSTAMP = 0
PCAP_MAX_LENGTH_CAP = 65535
PCAP_DATA_LINK_TYPE = 1
PCAP_HEADER_SIZE = 24
PCAP_TIMESTAMPS_SIZE = 16

#     Pcap Global Header Format :
#                       ( magic number +
#                         major version number +
#                         minor version number +
#                         GMT to local correction +
#                         accuracy of timestamps +
#                         max length of captured #packets, in octets +
#                         data link type)


def check_positive(value, type_):
    res = type_(value)
    if res < 0:
        raise ValueError()
    return res


class PcapFileManager:

    def __init__(self, flags):
        if flags:
            self.first_file = flags['name']
            self.count = ""
            self.flags = flags
            self.cur_file = self.first_file
            self.files = [self.first_file]
            self.cur_buffer = open(self.first_file, "wb")
            self.is_write_header = True
            self.time = time.time()
            self.packets = 0
            self.check_flags()

    def next_buffer(self):
        tokens = self.first_file.split('.')
        name_tokens = tokens[:-1]
        expansion = tokens[-1]
        name = ".".join(name_tokens) + str(self.count) + '.' + expansion
        self.files.append(name)
        if self.count == "":
            self.count = 1
        self.count += 1
        self.cur_buffer.close()
        self.cur_file = name
        return open(name, "wb")

    def check_flags(self):
        if "time" in self.flags:
            try:
                self.delay = check_positive(self.flags['time'], float)
            except ValueError:
                raise ParsingArgsError("expected positive float"
                                       " in key time but was : {}"
                                       .format(self.flags['time']))
        if "size" in self.flags:
            try:
                self.max_size = check_positive(self.flags['size'], int)
            except ValueError:
                raise ParsingArgsError("expected positive int"
                                       " in key size but was : {}"
                                       .format(self.flags['size']))
        if "filepackets" in self.flags:
            try:
                self.max_packets = check_positive(self.flags['filepackets'],
                                                  int)
            except ValueError:
                raise ParsingArgsError("expected positive int"
                                       " in key fp but was : {}"
                                       .format(self.flags['filepackets']))

    def is_next_file(self, data):
        if "time" in self.flags:
            cur_time = time.time()
            if cur_time - self.time >= self.delay:
                self.time = time.time()
                return True
        if "size" in self.flags:
            if len(data) >= self.max_size:
                return None
            cur_size = os.path.getsize(self.cur_file)
            if cur_size + len(data) >= self.max_size:
                return True
        if "filepackets" in self.flags:
            if self.packets >= self.max_packets:
                return True
        return False

    def write(self, data):
        pcap = Pcap()
        is_next_file = self.is_next_file(data)
        if is_next_file:
            self.packets = 0
            self.cur_buffer = self.next_buffer()
            self.is_write_header = True
        elif is_next_file is None:
            return None
        pcap.write(self.cur_buffer, data, self.is_write_header)
        self.is_write_header = False
        self.packets += 1

    def close(self):
        self.cur_buffer.close()


class Pcap:

    def __init__(self, link_type=PCAP_DATA_LINK_TYPE):
        self.link_type = link_type

    def write(self, buffer, data, is_write_header):
        if is_write_header:
            buffer.write(self.get_header())
        ts_sec, ts_usec = map(int, str(time.time()).split('.'))
        length = len(data)
        buffer.write(struct.pack(
            '@ I I I I', ts_sec, ts_usec, length, length))
        buffer.write(data)
        buffer.flush()

    def get_header(self):
        return struct.pack(PCAP_GLOBAL_HEADER_FMT,
                           PCAP_MAGICAL_NUMBER,
                           PCAP_MJ_VERN_NUMBER,
                           PCAP_MI_VERN_NUMBER,
                           PCAP_LOCAL_CORECTIN,
                           PCAP_ACCUR_TIMSTAMP,
                           PCAP_MAX_LENGTH_CAP,
                           self.link_type)

    def get_packets_from_pcap(self, buffer):
        header = buffer.read(PCAP_HEADER_SIZE)
        timestamps = buffer.read(PCAP_TIMESTAMPS_SIZE)
        while timestamps:
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
                '@ I I I I', timestamps)
            data = buffer.read(incl_len)
            timestamps = buffer.read(16)
            yield PacketInfo(data)
