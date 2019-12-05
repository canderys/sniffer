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
    settings_argument_group = ['link', 'view', 'data']
    parser = argparse.ArgumentParser(description='sniffer on raw sockets')
    parser.add_argument(
        '--output', '-o', help='output file name, saves in pcap format')
    parser.add_argument('--maxpackets', '-m', type=int,
                        help='maximum number of packets')
    output_settings = parser.add_argument_group('output settings')
    output_settings.add_argument(
        '--link', '-l', action='store_true', help='display link layer data')
    output_settings.add_argument(
        '--view', '-v', action='store_true',
        help='display detailed information')
    output_settings.add_argument(
        '--data', '-d', action='store_true',
        help='display information with packet data')
    return parser.parse_args(args), settings_argument_group


@contextmanager
def parsing_arguments(parser, settings_argument_group):
    actual_settings_argument = []
    for argument in settings_argument_group:
        if vars(parser)[argument]:
            actual_settings_argument.append(argument)
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
        yield output, maxpackets, actual_settings_argument
    finally:
        output.close()


def run(argv):
    if os.name == 'nt':
        raise IncorrectOsError("windows unsupported")
    parser, parsed_settings_argument = parse_args(argv)
    with parsing_arguments(parser, parsed_settings_argument) as arguments:
        output = arguments[0]
        maxpackets = arguments[1]
        settings_argument = arguments[2]
        network_sniffer = NetworkSniffer()
        network_writer = NetworkWriter(settings_argument)
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
