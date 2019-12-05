from sniffer import parse_args, parsing_arguments
import tempfile
import unittest


class TestSniffer(unittest.TestCase):

    def test_parse_args_correct(self):
        parser = parse_args(['-o', 'test.txt', '-m', '200'])
        self.assertEqual(parser.output, 'test.txt')
        self.assertEqual(parser.maxpackets, 200)
        parser = parse_args(['-o', 'test.txt'])
        self.assertEqual(parser.output, 'test.txt')
        self.assertEqual(parser.maxpackets, None)

    def test_parsing_arguments(self):
        out_file = tempfile.NamedTemporaryFile(delete=False)
        out_file.close()
        parser = parse_args(['-o', out_file.name, '-m', '200'])
        with parsing_arguments(parser) as arguments:
            self.assertEqual(arguments[1], 200)
            self.assertEqual(arguments[0].name, out_file.name)

    def test_IncorrectInputError(self):
        parser = parse_args(['-m', '-1'])
