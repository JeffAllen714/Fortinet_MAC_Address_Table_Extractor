import re
import sys
import csv
import paramiko
from PyQt6.QtGui import QColor
from typing import List, Dict, Optional
from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QLabel, QLineEdit, QPushButton, QProgressBar,
                             QTableWidget, QTableWidgetItem, QMessageBox, QFileDialog, QDialog, QScrollArea, QTextEdit)


class FortinetMacAddressExtractor:
    """
    A class to extract MAC address tables from Fortinet switches via SSH.
    """

    def __init__(self, ip: str, username: str, password: str):
        self.ip = ip
        self.username = username
        self.password = password
        self.sshClient: Optional[paramiko.SSHClient] = None
        self.macAddressTable: Optional[List[Dict[str, str]]] = None

    def connect(self) -> bool:
        self.sshClient = paramiko.SSHClient()
        self.sshClient.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.sshClient.connect(self.ip, username=self.username, password=self.password)
            return True
        except Exception as e:
            print(f"An error occurred while connecting: {e}")
            return False

    def getMacAddressTable(self) -> bool:
        if not self.sshClient:
            print("Not connected. Please call connect() first.")
            return False
        try:
            stdin, stdout, stderr = self.sshClient.exec_command("diag sw mac-addr list")
            error_message = stderr.read().decode('utf-8')
            if error_message:
                print(f"Command error: {error_message}")
                return False

            output = stdout.read().decode('utf-8')
            print(f"Raw output: {output}")  # Debug print

            if not output.strip():
                print("Empty output received.")
                return False

            self.macAddressTable = FortinetMacAddressExtractor.parseMacAddressTable(output)
            return True
        except Exception as e:
            print(f"An error occurred while getting MAC address table: {e}")
            return False
        finally:
            if self.sshClient:
                self.sshClient.close()

    @staticmethod
    def parseMacAddressTable(output: str) -> List[Dict[str, str]]:
        lines = output.strip().split('\n')
        parsedData = []
        entry = {}

        for line in lines:
            if line.startswith("MAC:"):
                if entry:
                    parsedData.append(entry)
                entry = {}
                mac_match = re.search(r"MAC:\s+([\w:]+)", line)
                vlan_match = re.search(r"VLAN:\s+(\d+)", line)
                port_match = re.search(r"Port:\s+([^\s]+)", line)
                if mac_match:
                    entry['macAddress'] = mac_match.group(1)
                if vlan_match:
                    entry['vlan'] = vlan_match.group(1)
                if port_match:
                    entry['port'] = port_match.group(1)
            elif line.strip().startswith("Flags:"):
                flags_match = re.search(r"Flags:\s+([^\s]+)\s+\[(.*?)\]", line)
                if flags_match:
                    entry['flags'] = f"{flags_match.group(1)} [{flags_match.group(2)}]"

        if entry:
            parsedData.append(entry)

        print("Parsed Data:", parsedData)  # Debug print
        return parsedData

    def writeToCsv(self, filename: str) -> bool:
        if not self.macAddressTable:
            print("No data to write. Please call getMacAddressTable() first.")
            return False

        try:
            with open(filename, 'w', newline='') as csvfile:
                fieldnames = ['macAddress', 'vlan', 'port', 'flags']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for row in self.macAddressTable:
                    writer.writerow(row)
            return True
        except Exception as e:
            print(f"An error occurred while writing to CSV: {e}")
            return False


class ExtractorThread(QThread):
    """
    This class extracts the threads from the MAC Address extractor to calculate %
    """

    updateProgress = pyqtSignal(int)
    extractionComplete = pyqtSignal(list)
    errorOccurred = pyqtSignal(str)

    def __init__(self, ip: str, username: str, password: str):
        super().__init__()
        self.ip = ip
        self.username = username
        self.password = password

    def run(self):
        extractor = FortinetMacAddressExtractor(self.ip, self.username, self.password)

        self.updateProgress.emit(20)
        if not extractor.connect():
            self.errorOccurred.emit("Failed to connect to the switch.")
            return

        self.updateProgress.emit(50)
        if not extractor.getMacAddressTable():
            self.errorOccurred.emit("Failed to retrieve MAC address table.")
            return

        self.updateProgress.emit(80)
        if extractor.macAddressTable:
            self.extractionComplete.emit(extractor.macAddressTable)
        else:
            self.errorOccurred.emit("No data retrieved from the switch.")

        self.updateProgress.emit(100)


class HelpDialog(QDialog):
    """
    Dialog window to display the README information.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Help - Fortinet MAC Address Table Extractor")
        self.setGeometry(150, 150, 600, 400)

        layout = QVBoxLayout()

        scroll = QScrollArea()
        content = QTextEdit()
        content.setReadOnly(True)
        content.setHtml(self.get_readme_content())

        scroll.setWidget(content)
        scroll.setWidgetResizable(True)

        layout.addWidget(scroll)
        self.setLayout(layout)

    def get_readme_content(self):
        # This method returns the README content as HTML
        return """
        <h1>Fortinet MAC Address Table Extractor</h1>

        <h2>Description</h2>
        <p>Fortinet MAC Address Table Extractor is a Python-based graphical application that allows users to extract the MAC address table from Fortinet switches. It provides a user-friendly interface to connect to a switch, retrieve the MAC address table, display the results, and export the data to a CSV file.</p>

        <h2>Features</h2>
        <ul>
            <li>Connect to Fortinet switches via SSH</li>
            <li>Extract MAC address tables</li>
            <li>Display results in a searchable table</li>
            <li>Highlight search results</li>
            <li>Export data to CSV</li>
            <li>Progress indication during extraction</li>
        </ul>

        <h2>Usage</h2>
        <ol>
            <li>Enter the IP address, username, and password for the Fortinet switch.</li>
            <li>Click "Extract MAC Address Table" to start the extraction process.</li>
            <li>Once completed, the results will be displayed in the table.</li>
            <li>Use the search bar to filter results.</li>
            <li>Click "Save to CSV" to export the data to a CSV file.</li>
        </ol>

        <h2>Security Note</h2>
        <p>This application stores passwords in memory and transmits them over SSH. Ensure you're using it in a secure environment and in compliance with your organization's security policies.</p>
        """


class MainWindow(QMainWindow):
    """
    Main window for the Fortinet MAC Address Extractor application.
    """

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Fortinet MAC Address Extractor")
        self.setGeometry(100, 100, 800, 600)
        mainWidget = QWidget()
        self.setCentralWidget(mainWidget)
        layout = QVBoxLayout()
        mainWidget.setLayout(layout)

        # Input fields
        inputLayout = QHBoxLayout()
        self.ipInput = QLineEdit()
        self.usernameInput = QLineEdit()
        self.passwordInput = QLineEdit()
        self.passwordInput.setEchoMode(QLineEdit.EchoMode.Password)
        inputLayout.addWidget(QLabel("IP:"))
        inputLayout.addWidget(self.ipInput)
        inputLayout.addWidget(QLabel("Username:"))
        inputLayout.addWidget(self.usernameInput)
        inputLayout.addWidget(QLabel("Password:"))
        inputLayout.addWidget(self.passwordInput)
        layout.addLayout(inputLayout)

        # Extract and Help buttons
        buttonLayout = QHBoxLayout()
        self.extractButton = QPushButton("Extract MAC Address Table")
        self.extractButton.clicked.connect(self.startExtraction)
        self.helpButton = QPushButton("Help")
        self.helpButton.clicked.connect(self.showHelp)
        buttonLayout.addWidget(self.extractButton)
        buttonLayout.addWidget(self.helpButton)
        layout.addLayout(buttonLayout)

        # Progress bar
        self.progressBar = QProgressBar()
        layout.addWidget(self.progressBar)

        # Search bar
        searchLayout = QHBoxLayout()
        self.searchInput = QLineEdit()
        self.searchInput.setPlaceholderText("Search...")
        self.searchInput.textChanged.connect(self.filterResults)
        searchLayout.addWidget(QLabel("Search:"))
        searchLayout.addWidget(self.searchInput)
        layout.addLayout(searchLayout)

        # Results table
        self.resultsTable = QTableWidget()
        self.resultsTable.setColumnCount(4)
        self.resultsTable.setHorizontalHeaderLabels(
            ["MAC Address", "VLAN", "Port", "Flags"])
        layout.addWidget(self.resultsTable)

        # Save button
        self.saveButton = QPushButton("Save to CSV")
        self.saveButton.clicked.connect(self.saveToCsv)
        self.saveButton.setEnabled(False)
        layout.addWidget(self.saveButton)

        # Initialize extractorThread and fullData
        self.extractorThread: Optional[ExtractorThread] = None
        self.fullData: List[Dict[str, str]] = []

    def showHelp(self):
        helpDialog = HelpDialog(self)
        helpDialog.exec()

    def startExtraction(self):
        ip = self.ipInput.text()
        username = self.usernameInput.text()
        password = self.passwordInput.text()

        if not all([ip, username, password]):
            QMessageBox.warning(self, "Input Error", "Please fill in all fields.")
            return

        self.extractButton.setEnabled(False)
        self.progressBar.setValue(0)

        self.extractorThread = ExtractorThread(ip, username, password)
        self.extractorThread.updateProgress.connect(self.updateProgress)
        self.extractorThread.extractionComplete.connect(self.displayResults)
        self.extractorThread.errorOccurred.connect(self.showError)
        self.extractorThread.start()

    def updateProgress(self, value: int):
        self.progressBar.setValue(value)

    def displayResults(self, data: List[Dict[str, str]]):
        self.fullData = data
        self.filterResults()
        self.extractButton.setEnabled(True)
        self.saveButton.setEnabled(True)

    def filterResults(self):
        searchText = self.searchInput.text().lower()
        filteredData = [entry for entry in self.fullData if
                        any(searchText in str(value).lower() for value in entry.values())]

        self.resultsTable.setRowCount(len(filteredData))
        for row, entry in enumerate(filteredData):
            for col, (key, value) in enumerate(entry.items()):
                item = QTableWidgetItem(str(value))
                if searchText in str(value).lower():
                    item.setBackground(QColor(255, 255, 0, 100))  # Light yellow highlight
                self.resultsTable.setItem(row, col, item)

    def showError(self, message: str):
        QMessageBox.critical(self, "Error", message)
        self.extractButton.setEnabled(True)

    def saveToCsv(self):
        filename, _ = QFileDialog.getSaveFileName(self, "Save CSV", "", "CSV Files (*.csv)")
        if filename:
            with open(filename, 'w', newline='') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=['macAddress', 'vlan', 'port', 'flags'])
                writer.writeheader()
                for entry in self.fullData:
                    writer.writerow(entry)
            QMessageBox.information(self, "Save Successful", f"Data saved to {filename}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
  
