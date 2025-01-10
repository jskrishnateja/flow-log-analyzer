import csv
import sys
from collections import defaultdict
from typing import Dict, Tuple


class FlowLogAnalyzer:
    """Class to analyze flow logs and map them to tags."""

    def __init__(self):
        self.lookup_table: Dict[Tuple[str, str], str] = {}
        self.tag_counts: Dict[str, int] = defaultdict(int)
        self.port_protocol_counts: Dict[Tuple[str, str], int] = defaultdict(int)

    def load_lookup_table(self, lookup_file: str):
        """Load and parse the lookup table CSV file."""
        try:
            with open(lookup_file, mode='r', encoding='ascii') as file:
                reader = csv.DictReader(file)
                if not {'dstport', 'protocol', 'tag'}.issubset(reader.fieldnames):
                    raise ValueError("Lookup file must have 'dstport', 'protocol', and 'tag' columns.")
                for row in reader:
                    dstport = row['dstport'].strip()
                    protocol = row['protocol'].strip().lower()  # Normalize protocol to lowercase
                    tag = row['tag'].strip().lower()  # Normalize tag to lowercase
                    # Store the tag for each port/protocol combination
                    self.lookup_table[(dstport, protocol)] = tag
        except Exception as e:
            print(f"Error loading lookup file: {e}")
            sys.exit(1)

    def process_flow_logs(self, flow_log_file: str):
        """Process flow logs and update counts."""
        try:
            with open(flow_log_file, mode='r', encoding='ascii') as file:
                for line in file:
                    self._process_log_line(line.strip())
        except Exception as e:
            print(f"Error processing flow logs: {e}")
            sys.exit(1)

    def _process_log_line(self, line: str):
        """Process a single log line and update counts."""
        fields = line.split()
        if len(fields) < 14 or fields[0] != '2':  # Validate version and field count
            return

        dstport = fields[6]
        protocol = self._normalize_protocol(fields[7])

        # Update port/protocol counts
        self.port_protocol_counts[(dstport, protocol)] += 1

        # Determine the tag from the lookup table
        tag = self.lookup_table.get((dstport, protocol), "untagged")
        self.tag_counts[tag] += 1

    @staticmethod
    def _normalize_protocol(protocol: str) -> str:
        """Normalize protocol values for consistency."""
        mapping = {'6': 'tcp', '17': 'udp', '1': 'icmp'}
        return mapping.get(protocol, protocol.lower())

    def write_results(self, output_file: str):
        """Write analysis results to the output file."""
        with open(output_file, mode='w', encoding='ascii') as file:
            # Write Tag Counts
            file.write("Count of matches for each tag\n\n")
            file.write("Tag Counts:\n")
            file.write("Tag,Count\n")
            for tag, count in sorted(self.tag_counts.items(), key=lambda x: (x[0] != "untagged", x[0])):
                file.write(f"{tag},{count}\n")

            # Write Port/Protocol Combination Counts
            file.write("\nCount of matches for each port/protocol combination\n\n")
            file.write("Port/Protocol Combination Counts:\n")
            file.write("Port,Protocol,Count\n")
            for (port, protocol), count in sorted(
                self.port_protocol_counts.items(),
                key=lambda x: (int(x[0][0]) if x[0][0].isdigit() else float('inf'), x[0][1])
            ):
                file.write(f"{port},{protocol},{count}\n")


def main():
    if len(sys.argv) < 3:
        print("Usage: python flow_log_analyzer.py <flow_log_file> <lookup_file>")
        sys.exit(1)

    flow_log_file = sys.argv[1]
    lookup_file = sys.argv[2]
    output_file = "output_results.txt"

    analyzer = FlowLogAnalyzer()
    analyzer.load_lookup_table(lookup_file)
    analyzer.process_flow_logs(flow_log_file)
    analyzer.write_results(output_file)

    print(f"Analysis complete. Results written to {output_file}")


if __name__ == "__main__":
    main()
