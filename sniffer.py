import argparse
import sys
import socket
import math
import os
from moduls.NetworkSniffer import NetworkSniffer
from moduls.NetworkWriter import NetworkWriter
from moduls.exceptions import IncorrectInputError, SnifferError, \
    IncorrectOsError
from moduls.Pcap import Pcap
from contextlib import contextmanager


def parse_args(args):
    parser = argparse.ArgumentParser(description='sniffer on raw sockets')
    parser.add_argument(
        '--output', '-o', help='output file name, saves in pcap format')
    parser.add_argument('--maxpackets', '-m', type=int,
                        help='maximum number of packets')
    return parser.parse_args(args)


@contextmanager
def parsing_arguments(parser):
    try:
        output = sys.stdout
        if parser.output:
            output = open(parser.output, "wb")
        maxpackets = math.inf
        if parser.maxpackets:
            if parser.maxpackets <= 0:
                raise IncorrectInputError(
                    "  maximum number of packets must be greater than 0")
            maxpackets = parser.maxpackets
        yield output, maxpackets
    finally:
        output.close()


def run(argv):
    print(os.name)
    parser = parse_args(argv)
    with parsing_arguments(parser) as arguments:
        output = arguments[0]
        maxpackets = arguments[1]
        network_sniffer = NetworkSniffer()
        network_writer = NetworkWriter()
        is_pcap_write = False
        if output is not sys.stdout:
            is_pcap_write = True
            output = Pcap(output)
        for packet in network_sniffer.get_packets(maxpackets):
            if is_pcap_write:
                output.write(packet.raw_data)
            else:
                output.write(network_writer.get_packet_info(packet))


if __name__ == '__main__':
    try:
        run(sys.argv[1:])
    except SnifferError as e:
        print(e, file=sys.stderr)
        sys.exit(e.code)
    except PermissionError:
        print("PermissionError: use sudo", file=sys.stderr)
        sys.exit(2)
