# Mapo_Network-Scanning-Tool

Steps to Run the Network Scanning Tool:

1. **Set Up the Environment**
   - Ensure Python 3.x is installed on the system.
   - Open a terminal (or command prompt) and navigate to the directory where the tool is located.

2. **Install Required Dependencies**
   - The instructor needs to install all the necessary Python libraries to run the script. This can be done using `pip` by running the following command:
     ```
     pip install scapy requests paramiko
     ```
     This command installs:
     - **scapy**: for network packet crafting and scanning.
     - **requests**: for making API requests to fetch CVE data.
     - **paramiko**: for SSH credential checks.

3. **Prepare the Python Script**
   - The Python script should already be in a file (e.g., `network_scanner.py`). Make sure this file is accessible.

4. **Run the Python Script**
   - The instructor can run the tool with specific arguments by opening the terminal or command prompt in the directory where the script is located and typing the following command:
     ```bash
     python network_scanner.py -n <network_range> -p <ports> -o <output_file>
     ```
   - **Example Command**:
     ```bash
     python network_scanner.py -n 192.168.0.0/24 -p 22,80,443 -o results.json
     ```
     This command does the following:
     - Scans the network range `192.168.0.0/24`.
     - Checks for open ports `22, 80, 443`.
     - Saves the results in a file called `results.json`.

5. **Command-Line Argument Explanation**:
   - **`-n` (or `--network`)**: Required. The network range to scan in CIDR format (e.g., `192.168.1.0/24`).
   - **`-p` (or `--ports`)**: Optional. A comma-separated list of ports to scan (default: `21,22,80,443`).
   - **`-o` (or `--output`)**: Optional. The filename to save the scan results in JSON format (default: `scan_results.json`).

6. **Viewing the Results**
   - Once the scan completes, results will be shown in the terminal.
   - If the `-o` argument was used, results will also be saved to the specified JSON file for further review.


