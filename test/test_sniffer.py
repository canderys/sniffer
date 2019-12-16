from sniffer import parse_args, \
    parsing_arguments
import tempfile
import unittest


class TestParseArgs(unittest.TestCase):

    def test_parsing_arguments(self):
        out_file = tempfile.NamedTemporaryFile(delete=False)
        out_file.close()
        parser, parsed_settings_argument, parsed_sniffer_settings = parse_args(
            ['-o', out_file.name, '-m', '200'])
        with parsing_arguments(parser, parsed_settings_argument,
                               parsed_sniffer_settings) as arguments:
            self.assertEqual(arguments[1], 200)
            self.assertEqual(arguments[0].name, out_file.name)

    def test_parsing_tcp(self):
        parser, parsed_settings_argument, parsed_sniffer_settings = parse_args(
            ['--tcp'])
        self.assertEqual(parser.tcp, True)
