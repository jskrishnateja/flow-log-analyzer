import unittest
from io import StringIO
from unittest.mock import patch, mock_open
from flow_log_analyzer import FlowLogAnalyzer


class TestFlowLogAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = FlowLogAnalyzer()

    @patch("builtins.open", mock_open(read_data="dstport,protocol,tag\n25,tcp,sv_p1\n68,udp,sv_p2"))
    def test_load_lookup_table(self):
        self.analyzer.load_lookup_table('lookup_table.csv')
        self.assertIn(('25', 'tcp'), self.analyzer.lookup_table)
        self.assertEqual(self.analyzer.lookup_table[('25', 'tcp')], 'sv_p1')
        self.assertIn(('68', 'udp'), self.analyzer.lookup_table)
        self.assertEqual(self.analyzer.lookup_table[('68', 'udp')], 'sv_p2')

    @patch("builtins.open", mock_open(read_data="dstport,protocol,tag\n25,tcp,sv_p1\n68,udp,sv_p2"))
    def test_process_log(self):
        self.analyzer.load_lookup_table('lookup_table.csv')

        # Simulating a flow log with matching and non-matching entries
        flow_log_data = "2 0 0 0 0 0 25 tcp 10.0.0.1 10.0.0.2 1 1 1 1\n"  # Matches sv_p1
        with patch("builtins.open", mock_open(read_data=flow_log_data)):
            self.analyzer.process_flow_logs('flow_logs.csv')

        # Check the tag counts after processing
        self.assertEqual(self.analyzer.tag_counts['sv_p1'], 1)
        self.assertEqual(self.analyzer.tag_counts['sv_p2'], 0)  # No sv_p2 match

    @patch("builtins.open", mock_open(read_data="dstport,protocol,tag\n25,tcp,sv_p1\n68,udp,sv_p2"))
    def test_process_log_multiple_tags(self):
        self.analyzer.load_lookup_table('lookup_table.csv')

        # Simulating flow logs with multiple matching tags
        flow_log_data = """2 0 0 0 0 0 25 tcp 10.0.0.1 10.0.0.2 1 1 1 1
                           2 0 0 0 0 0 68 udp 10.0.0.1 10.0.0.2 1 1 1 1"""  # Matches sv_p1 and sv_p2
        with patch("builtins.open", mock_open(read_data=flow_log_data)):
            self.analyzer.process_flow_logs('flow_logs.csv')

        # Check the tag counts after processing
        self.assertEqual(self.analyzer.tag_counts['sv_p1'], 1)
        self.assertEqual(self.analyzer.tag_counts['sv_p2'], 1)

    @patch("builtins.open", mock_open(read_data="dstport,protocol,tag\n25,tcp,sv_p1\n68,udp,sv_p2"))
    def test_untagged_log(self):
        self.analyzer.load_lookup_table('lookup_table.csv')

        # Simulating a log that does not match any tag in the lookup table
        flow_log_data = "2 0 0 0 0 0 9999 tcp 10.0.0.1 10.0.0.2 1 1 1 1"  # No match
        with patch("builtins.open", mock_open(read_data=flow_log_data)):
            self.analyzer.process_flow_logs('flow_logs.csv')

        # Check that the untagged count is incremented
        self.assertEqual(self.analyzer.tag_counts['untagged'], 1)

    @patch("builtins.open", mock_open(read_data="dstport,protocol,tag\n25,tcp,sv_p1\n68,udp,sv_p2"))
    def test_result_file_format(self):
        self.analyzer.load_lookup_table('lookup_table.csv')

        # Simulating some flow logs
        flow_log_data = """2 0 0 0 0 0 25 tcp 10.0.0.1 10.0.0.2 1 1 1 1
                           2 0 0 0 0 0 68 udp 10.0.0.1 10.0.0.2 1 1 1 1"""
        with patch("builtins.open", mock_open(read_data=flow_log_data)):
            self.analyzer.process_flow_logs('flow_logs.csv')

        # Check if the result file is written correctly
        with patch("builtins.open", mock_open()) as mocked_file:
            self.analyzer.write_results('output_results.txt')
            mocked_file.assert_called_with('output_results.txt', mode='w', encoding='ascii')
            handle = mocked_file()
            handle.write.assert_any_call("Tag,Count\n")
            handle.write.assert_any_call("sv_p1,1\n")
            handle.write.assert_any_call("sv_p2,1\n")


if __name__ == "__main__":
    unittest.main()
