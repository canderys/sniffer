from sniffer import parse_args, \
    parsing_arguments
import unittest
from moduls.sniffer_core import IncorrectInputError


class TestParseArgs(unittest.TestCase):

    def test_parsing_arguments(self):
        parser = parse_args(['-m', '200', '-i', 'eth0'])
        with parsing_arguments(parser) as arguments:
            self.assertEqual(arguments[1], 200)
            self.assertEqual(arguments[3]['interface'], 'eth0')

    def incorrect_max_packets(self):
        parser = parse_args(['-m', '-1'])
        with parsing_arguments(parser):
            self.assertEqual(parser.maxpackets, -1)

    def test_incorrect_max_packets(self):
        self.assertRaises(IncorrectInputError, self.incorrect_max_packets)

    def test_filtr(self):
        parser = parse_args(['-c' 'scr port 443'])
        self.assertEqual(parser.condition, "scr port 443")
