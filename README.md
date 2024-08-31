# Fortinet_MAC_Address_Table_Extractor
Fortinet MAC Address Table Extractor is a Python-based GUI application that allows network administrators to easily extract MAC address tables from Fortinet switches via SSH. This tool provides a user-friendly interface for connecting to switches, retrieving MAC address tables, displaying results, and exporting data to CSV files.

## Features
- Connect to Fortinet switches via SSH
- Extract MAC address tables
- Display results in a searchable table
- Highlight search results
- Export data to CSV
- Progress indication during extraction

## Requirements
- Python 3.x
- PyQt6
- paramiko

## Installation
1. Ensure you have Python 3.x installed on your system.
2. Install the required dependencies:
   ```
   pip install PyQt6 paramiko
   ```

## Usage
1. Run the script:
   ```
   python fortinet_mac_extractor.py
   ```
2. Enter the IP address, username, and password for the Fortinet switch.
3. Click "Extract MAC Address Table" to start the extraction process.
4. Once completed, the results will be displayed in the table.
5. Use the search bar to filter results.
6. Click "Save to CSV" to export the data to a CSV file.

## Code Structure
- `FortinetMacAddressExtractor`: Class for connecting to the switch and extracting MAC address tables.
- `ExtractorThread`: QThread subclass for running the extraction process in the background.
- `MainWindow`: Main application window and GUI implementation.

## Error Handling
The application includes error handling for common issues such as connection failures or data retrieval problems. Error messages are displayed to the user via message boxes.

## Security Note
This application stores passwords in memory and transmits them over SSH. Ensure you're using it in a secure environment and in compliance with your organization's security policies.

## Contributing
Contributions to improve the Fortinet MAC Address Table Extractor are welcome. Please feel free to submit pull requests or open issues for bugs and feature requests.
