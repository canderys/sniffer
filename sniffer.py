import argparse
import sys
import socket
import math
import os
from moduls.sniffer_core import (NetworkSniffer, NetworkWriter,
                                 Pcap, PcapFileManager, IncorrectInputError,
                                 SnifferError, IncorrectOsError,
                                 ParsingArgsError)
from contextlib import contextmanager
from enum import Enum


PacketSource = Enum('PacketSource', 'network')

SETTINGS_ARGUMENT_GROUP = ['link', 'view', 'data', 'color']
SNIFFER_SETTINGS_GROUP = ['interface', 'condition']
OUTPUT_INDEX = 0
MAXPACKETS_INDEX = 1
SETTINGS_INDEX = 2
SNIFFER_INDEX = 3
PACKET_SOURCE_INDEX = 4


def parse_args(args):
    parser = argparse.ArgumentParser(description='sniffer on raw sockets')

    subparsers = parser.add_subparsers(help='sub-command help')
    parser_out = subparsers.add_parser('pcap',
                                       help='key for recording packets \
                                       in pcap format')
    parser_out.add_argument('--name', '-n', type=str,
                            help='set name file', required=True)
    parser_out.add_argument('--time', '-t',
                            help="time to write packets to a file in seconds")
    parser_out.add_argument('--size', '-s',
                            help="set max size pcap file in bites")
    parser_out.add_argument('--filepackets', '-fp',
                            help="set max number of packets in file")

    parser.add_argument(
        '--read', '-r', help='read from pcap format')
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
    output_settings.add_argument("--color", action='store_true',
                                 help="incoming packets are colored"
                                 " in blue, sent in red")

    sniffer_settings = parser.add_argument_group('sniffer settings')
    sniffer_settings.add_argument(
        '--interface', '-i', help="set network interface")
    sniffer_settings.add_argument(
        "--condition", "-c", help="network packets condition")

    return parser.parse_args(args)


def get_output(parser):
    output_settings = ['name', 'time', 'size', 'filepackets']
    actual_output_settings = get_actual_arguments(parser, output_settings)
    return actual_output_settings


def get_actual_arguments(parser, expected_arguments):
    actual_arguments = {}
    for argument in expected_arguments:
        if vars(parser).get(argument):
            actual_arguments[argument] = vars(parser)[argument]
    return actual_arguments


def try_open(file, mode):
    try:
        return open(file, mode)
    except (FileNotFoundError, OSError):
        raise ParsingArgsError(
            "Error : unable to open file {}".format(file))


@contextmanager
def parsing_arguments(parser):
    actual_settings_arguments = get_actual_arguments(
        parser, SETTINGS_ARGUMENT_GROUP)
    actual_sniffer_settings = get_actual_arguments(
        parser, SNIFFER_SETTINGS_GROUP)
    if "color" in actual_settings_arguments and parser.read:
        raise IncorrectInputError("incompatible keys r and color")
    try:
        output = None
        packetSource = PacketSource.network
        if parser.read:
            packetSource = try_open(parser.read, "rb")
        output = sys.stdout
        if vars(parser).get('name'):
            output = PcapFileManager(get_output(parser))
        maxpackets = math.inf
        if parser.maxpackets:
            if parser.maxpackets <= 0:
                raise IncorrectInputError(
                    "Error : maximum number of packets must be greater than 0")
            maxpackets = parser.maxpackets
        yield output, maxpackets, actual_settings_arguments, \
            actual_sniffer_settings, packetSource
    finally:
        if output and output != sys.stdout:
            output.close()
        if packetSource != PacketSource.network:
            packetSource.close()


def run(argv):
    if os.name == 'nt':
        raise IncorrectOsError("Error : windows unsupported")
    parser = parse_args(argv)
    with parsing_arguments(parser) as arguments:
        output = arguments[OUTPUT_INDEX]
        maxpackets = arguments[MAXPACKETS_INDEX]
        settings_argument = arguments[SETTINGS_INDEX]
        sniffer_argument = arguments[SNIFFER_INDEX]
        packetSource = arguments[PACKET_SOURCE_INDEX]
        network_writer = NetworkWriter(settings_argument)
        is_pcap_write = False
        if output is not sys.stdout:
            is_pcap_write = True
        packet_generator = None
        network_sniffer = None
        if packetSource != PacketSource.network:
            packets_from_pcap = Pcap()
            packet_generator = packets_from_pcap.\
                get_packets_from_pcap(packetSource)
            network_sniffer = NetworkSniffer(
                packet_generator, flags=sniffer_argument)
        else:
            network_sniffer = NetworkSniffer(
                flags=sniffer_argument)
        for (parsed_packet, packet_info) in network_sniffer.\
                get_packets(maxpackets):
            if is_pcap_write:
                output.write(packet_info.data)
            else:
                output.write(network_writer.get_packet_info(
                    parsed_packet, packet_info))


if __name__ == '__main__':
    try:
        run(sys.argv[1:])
    except SnifferError as e:
        print(e, file=sys.stderr)
        sys.exit(e.CODE)
    except PermissionError:
        print("PermissionError: use sudo", file=sys.stderr)
        sys.exit(2)
