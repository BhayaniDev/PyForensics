# PyForensics
A cross-platform digital forensics tool that automates browser history analysis and USB device tracking with professional PDF reporting.

🕵️ PyForensics: Digital Investigation Platform
PyForensics is a modular, cross-platform digital forensics tool designed to automate the extraction and analysis of browser history and system artifacts. It generates court-admissible PDF reports while maintaining the Chain of Custody through cryptographic hashing.

Why this project? 
-Built to demonstrate core Digital Forensics concepts (Artifact Parsing, Evidence Integrity, and Reporting) for academic research and SOC automation.

🚀 Key Features
🌐 Browser Forensics: Extracts and analyzes history from Google Chrome and Mozilla Firefox.

🔌 USB Device Forensics: Parses the Windows SYSTEM Registry Hive to identify previously connected USB devices (Manufacturer, Model, Serial Number, Timestamp).

🛡️ Chain of Custody: automatically calculates MD5 Hashes of all evidence files before analysis to ensure data integrity.

📄 Automated Reporting: Generates a professional PDF Report containing all findings, sorted chronologically.

💻 Dual Interface:

CLI Mode: For quick, surgical analysis via terminal.

GUI Mode: User-friendly Tkinter dashboard for point-and-click investigation.

🐧 Cross-Platform: Auto-detects OS (Windows/Linux) and adjusts paths dynamically.

🛠️ Installation & Setup
Prerequisites
Python 3.x

Kali Linux (Recommended) or Windows
