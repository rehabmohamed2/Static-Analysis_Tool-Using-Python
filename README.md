# 📖 Project Overview

The **Static-Analysis-Tool** is designed for analyzing Portable Executable (PE) files and performing online malware scans using VirusTotal. This tool provides detailed insights into PE file headers, sections, imported/exported functions, and resource information. Additionally, it computes file hashes (MD5, SHA1, SHA256), extracts strings, calculates entropy, and integrates with VirusTotal for malware detection.

---

## 🌟 Features

### PE File Analysis:
- Extract and display header information (DOS, File, and Optional headers).
- Analyze sections and calculate entropy for each section.

### Hash Calculation:
- Generate MD5, SHA1, and SHA256 hashes for the selected file.

### String Extraction:
- Extract readable strings from the binary data.

### VirusTotal Integration:
- Check the file's SHA256 hash with VirusTotal to determine if it is flagged as malicious.

### Interactive GUI:
- Simple and user-friendly interface using Tkinter.
- Ability to select files and display results in a scrolling text widget.

---

## 🛠️ Tech Stack

- **Programming Language**: Python
- **Libraries Used**:
  - `pefile` for PE file analysis
  - `hashlib` for hash calculation
  - `tkinter` for GUI
  - `requests` for VirusTotal API integration
  - `re` and `math` for additional functionality

---

## 🚀 Getting Started

### Prerequisites
1. Python 3.7+
2. Required libraries:
   ```bash
   pip install pefile tk requests
   ```

3. Obtain a VirusTotal API key from [VirusTotal](https://www.virustotal.com/) and add it to the script:
   ```python
   VIRUSTOTAL_API_KEY = 'YOUR_API_KEY'
   ```

---

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/rehabmohamed2/Static-Analysis-Tool.git
   cd Static-Analysis-Tool
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the application:
   ```bash
   python static_analysis_tool.py
   ```

---

## 📂 Project Structure

```
Static-Analysis-Tool/
├── static_analysis_tool.py  # Main Python script
├── README.md                # Project documentation
└── requirements.txt         # Python dependencies
```

---

## 🖼️ Preview

### Screenshot
Add a screenshot here.

---

## 📈 Future Enhancements
- Add support for additional file formats.
- Include advanced malware analysis features.
- Provide a CLI version for script-based usage.
- Enhance GUI design with more interactivity and visualizations.

---

## 📜 License
This project is licensed under the [MIT License](LICENSE).

---

## 🤝 Contributing

Contributions are welcome! Follow these steps:
1. Fork the repository.
2. Create a new branch:
   ```bash
   git checkout -b feature-name
   ```
3. Commit your changes:
   ```bash
   git commit -m 'Add new feature'
   ```
4. Push to the branch:
   ```bash
   git push origin feature-name
   ```
5. Open a pull request.

---

## 📧 Contact

For any inquiries, feel free to reach out:

- [GitHub](https://github.com/rehabmohamed2)
- Email: [rehabmohamed151220@gmail.com]
---

