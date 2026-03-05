# 🚀 Cyber Security & Forensics Documentation

This document contains the README for the **Web Application Vulnerability Scanner** project and the technical walkthrough for **Cyber Forensics Lab 4 (FAT32 Analysis)** on Ubuntu.

---

## 🛡️ Web Application Vulnerability Scanner

A Python-based automated tool to scan web applications for common security vulnerabilities such as SQL Injection, Cross-Site Scripting (XSS), CSRF misconfigurations, open directories, and security header issues. This project is built for learning and demonstration purposes on intentionally vulnerable applications.

### 📌 Features
* **Crawl** target website and collect internal links.
* **Detect**:
    * SQL Injection vulnerabilities.
    * Cross-Site Scripting (XSS).
    * Missing CSRF protection.
    * Directory and file exposure.
    * Weak or missing HTTP security headers.
* **Generate scan reports** in Console, JSON, or HTML format.
* **Modular design** for easy extension.

### 🧰 Tech Stack
* **Language**: Python 3
* **Libraries**: `requests`, `beautifulsoup4`, `argparse`, `json`, `socket`
* **Optional**: `flask` (web UI), `nmap` (port scanning)

### ⚠️ Legal & Ethical Disclaimer
This tool is for educational purposes only. Scan only your own applications, localhost, or platforms like DVWA/WebGoat. **Do NOT scan real websites without permission.**

### 🗂️ Project Structure
```text
vuln_scanner/
│
├── scanner.py          # Main entry point
├── crawler.py          # URL discovery logic
├── attacks/            # Payload modules
│   ├── sql_injection.py
│   ├── xss.py
│   └── csrf.py
├── report/             # Reporting engine
│   ├── report_generator.py
│   └── template.html
├── output/             # Saved results
└── README.md

🚀 Installation & UsageBash# Clone and setup
git clone [https://github.com/yourusername/vuln-scanner.git](https://github.com/yourusername/vuln-scanner.git)
cd vuln-scanner
pip install -r requirements.txt

# Run scans
python scanner.py http://localhost/dvwa
python scanner.py [http://targetsite.com](http://targetsite.com) --sql --xss
📂 Cyber Forensics Lab 4: FAT32 Analysis (Ubuntu)This section provides the specific commands and offsets required to complete the analysis of Evidence_Lab4.001 using terminal tools (Sleuth Kit) and a hex editor (Ghex).🛠️ PrerequisitesBashsudo apt update && sudo apt install sleuthkit ghex -y
1️⃣ Exercise 2: Directory Entry AnalysisBrowse the File System:Use fls to find the metadata address (inode) of deleted files.Bash# List all files recursively starting at sector 2048
fls -o 2048 -r Evidence_Lab4.001
Identified Inode for Secret.txt: 46 (marked with * indicating deleted).Locate Root Directory in Hex:Root Dir Offset: 3,162,112 bytes (Hex: 0x304000).Action: Open Evidence_Lab4.001 in Ghex, press Ctrl+G, and go to 304000.Find Entry: Look for the string E5 53 65 63 72 65 74 (_ecret.txt).2️⃣ Exercise 3: Deleted File RecoveryAnalyse Deletion in Hex:FAT1 Start: 16,384 bytes (Hex: 0x4000).Action: Go to the FAT offset for the starting cluster of Secret.txt. Verify the entry is 00 00 00 00 (zeroed upon deletion).Manual Recovery:Extract the file using the metadata address found earlier.Bash# Extract file 46 to a new text file
icat -o 2048 Evidence_Lab4.001 46 > recovered_secret.txt

# View content
cat recovered_secret.txt
❓ Lab Questions Quick-ReferenceWhy is data intact? Deletion only marks the first character of the directory entry as 0xE5 and zeros the FAT chain; actual data remains until overwritten.When is recovery impossible? If the clusters have been allocated to a new file and the data has been overwritten.LFN to SFN Check: Verify the checksum byte in the LFN entry matches the hash of the 8.3 short filename