# Flow Log Analyzer

This project contains a Python script that processes flow logs and maps them to tags based on a given lookup table. The script reads flow log lines, normalizes the protocols, matches them with tags from the lookup table, and generates analysis results for both tag counts and port/protocol combinations.

## Assumptions
- The lookup table (`lookup_table.csv`) is expected to be in CSV format with columns: `dstport`, `protocol`, and `tag`.
- Flow logs are assumed to be in a text file format, where each line contains the flow log information.
- Protocols in the lookup table should be normalized to lowercase.
- Flow logs should be in a format where the protocol is represented by a number (e.g., `6` for TCP, `17` for UDP, `1` for ICMP).

## Files

### `flow_log_analyzer.py`

This is the main script responsible for loading the lookup table, processing the flow logs, and generating the analysis results.

### `test_flow_log_analyzer.py`

This file contains unit tests to verify the functionality of the `FlowLogAnalyzer` class. The tests cover scenarios such as processing logs with matching tags, handling protocols, and generating the correct output format.

### `lookup_table.csv`

This file contains the mapping between `dstport`, `protocol`, and `tag`. Example:

dstport,protocol,tag 
25,tcp,sv_P1 
68,udp,sv_P2 
23,tcp,sv_P1 
31,udp,SV_P3 
443,tcp,sv_P2 
22,tcp,sv_P4 
3389,tcp,sv_P5 
0,icmp,sv_P5 
110,tcp,email 
993,tcp,email 
143,tcp,email


### `flow_logs.txt`

This file contains the flow log lines that are processed by the script. Each line corresponds to a flow record with various fields, including the destination port and protocol.

## How to Run the Code

1. Clone the repository or download the files.
2. Make sure you have a `lookup_table.csv` and `flow_logs.txt` file ready with the appropriate data.
3. To run the main analysis script, use the following command:
   ```bash
   python flow_log_analyzer.py flow_logs.txt lookup_table.csv
This will process the flow logs and generate the results in a file named output_results.txt.

#### Unit Tests
The repository contains unit tests to verify the correctness of the script. To run the tests, use the following command:
   ```bash
   python -m unittest test_flow_log_analyzer.py

## Test Cases
Test processing of a single flow log line (test_process_log):
This test simulates processing a single flow log line and checks if the corresponding tag is counted correctly.
Test processing of flow logs with multiple matching tags (test_process_log_multiple_tags):
This test processes multiple flow logs with the same destination port and protocol, and verifies the correct count for matching tags.
Test that the protocol is normalized to lowercase (test_normalize_protocol):
This test ensures that the protocol (e.g., TCP or tcp) is normalized to lowercase before matching.
Test a scenario where multiple tags are assigned for the same port/protocol combination (test_multiple_tags_for_one_port_protocol):
This test verifies that the analyzer correctly handles cases where multiple tags are associated with the same port/protocol combination.
Test handling of a log line that does not match any tags in the lookup table (test_untagged_log):
This test checks that when a flow log line does not match any tags in the lookup table, the analyzer properly counts it as "untagged".
Example Output
The results of the analysis will be written to an output_results.txt file, which will contain:

The count of matches for each tag
The count of matches for each port/protocol combination
Example output_results.txt:

mathematica
Copy code
Count of matches for each tag

Tag Counts:
Tag,Count
sv_p1,3
sv_p2,4
untagged,2

Count of matches for each port/protocol combination

Port/Protocol Combination Counts:
Port,Protocol,Count
80,tcp,3
443,tcp,2
25,tcp,1
68,udp,2


