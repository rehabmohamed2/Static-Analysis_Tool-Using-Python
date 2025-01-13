import pefile
import hashlib
import re
import math
import datetime
import tkinter as tk
from tkinter import filedialog, scrolledtext, ttk
import requests

VIRUSTOTAL_API_KEY = 'YOUR_API'

def calculate_hashes(file_path):
    hashes = {
        'md5': hashlib.md5(), 
        'sha1': hashlib.sha1(), 
        'sha256': hashlib.sha256()}
    
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                for hash_alg in hashes.values():
                    hash_alg.update(chunk)
    except IOError:
        print(f"Error: Unable to open file {file_path}.")
        return None
    
    return {name: hash_alg.hexdigest() for name, hash_alg in hashes.items()}

def extract_strings(file_path, min_length=4):
    strings = []
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
            strings = re.findall(b'[\x20-\x7E]{' + str(min_length).encode() + b',}', data)
    except IOError:
        print(f"Error: Unable to open file {file_path}.")
        return None
    
    return [s.decode('utf-8', errors='ignore') for s in strings]

def calculate_entropy(data):
    if not data:
        return 0.0
    entropy = 0
    data_len = len(data)
    for x in range(256):
        p_x = float(data.count(x)) / data_len
        if p_x > 0:
            entropy -= p_x * math.log(p_x, 2)
    return entropy

def analyze_pe(file_path, text_widget):
    hashes = calculate_hashes(file_path)
    if hashes is None:
        return
    
    try:
        pe = pefile.PE(file_path)
    except pefile.PEFormatError:
        text_widget.insert(tk.END, f"Error: {file_path} is not a valid PE file.\n")
        return

    text_widget.insert(tk.END, f"Analyzing {file_path}...\n\n")
    
    text_widget.tag_configure("bold", font=("Helvetica", 10, "bold"))
    text_widget.tag_configure("underline", underline=True)

    text_widget.insert(tk.END, "Hash Codes:\n", "bold")
    for name, hash_code in hashes.items():
        text_widget.insert(tk.END, f"  {name.upper()}: {hash_code}\n")
    text_widget.insert(tk.END, "\n")
    time= int(hex(pe.FILE_HEADER.TimeDateStamp),16)
    human_date =datetime.datetime.fromtimestamp(time)
    text_widget.insert(tk.END, "Header Information:\n", "bold")
    text_widget.insert(tk.END, "  DOS Header:\n")
    text_widget.insert(tk.END, f"    e_magic: {hex(pe.DOS_HEADER.e_magic)}\n")
    text_widget.insert(tk.END, f"    e_lfanew: {hex(pe.DOS_HEADER.e_lfanew)}\n")
    text_widget.insert(tk.END, "  File Header:\n")
    text_widget.insert(tk.END, f"    Machine: {hex(pe.FILE_HEADER.Machine)}\n")
    text_widget.insert(tk.END, f"    NumberOfSections: {pe.FILE_HEADER.NumberOfSections}\n")
    text_widget.insert(tk.END, f"    TimeDateStamp: {human_date}\n")
    text_widget.insert(tk.END, f"    Characteristics: {hex(pe.FILE_HEADER.Characteristics)}\n")
    text_widget.insert(tk.END, "  Optional Header:\n")
    text_widget.insert(tk.END, f"    AddressOfEntryPoint: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}\n")
    text_widget.insert(tk.END, f"    ImageBase: {hex(pe.OPTIONAL_HEADER.ImageBase)}\n")
    text_widget.insert(tk.END, f"    FileAlignment: {pe.OPTIONAL_HEADER.FileAlignment}\n")
    text_widget.insert(tk.END, f"    SectionAlignment: {pe.OPTIONAL_HEADER.SectionAlignment}\n")
    text_widget.insert(tk.END, f"    SizeOfImage: {pe.OPTIONAL_HEADER.SizeOfImage}\n")
    text_widget.insert(tk.END, "\n")

    text_widget.insert(tk.END, "Sections:\n", "bold")
    for section in pe.sections:
        entropy = calculate_entropy(section.get_data())
        text_widget.insert(tk.END, f"  {section.Name.decode().strip()}:\n")
        text_widget.insert(tk.END, f"    Virtual Address: 0x{section.VirtualAddress:X}\n")
        text_widget.insert(tk.END, f"    Virtual Size: 0x{section.Misc_VirtualSize:X}\n")
        text_widget.insert(tk.END, f"    Raw Size: 0x{section.SizeOfRawData:X}\n")
        text_widget.insert(tk.END, f"    Characteristics: 0x{section.Characteristics:X}\n")
        text_widget.insert(tk.END, f"    Entropy: {entropy:.2f}\n")
        text_widget.insert(tk.END, "\n")

    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        text_widget.insert(tk.END, "Imported DLLs and functions:\n", "bold")
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            text_widget.insert(tk.END, f"  {entry.dll.decode()}:\n")
            for imp in entry.imports:
                text_widget.insert(tk.END, f"    {imp.name.decode() if imp.name else 'Ordinal'}\n")
            text_widget.insert(tk.END, "\n")

    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        text_widget.insert(tk.END, "Exported functions:\n", "bold")
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            text_widget.insert(tk.END, f"  {exp.name.decode() if exp.name else 'Ordinal'} (0x{exp.address:X})\n")
        text_widget.insert(tk.END, "\n")

    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        text_widget.insert(tk.END, "Resources:\n", "bold")
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            text_widget.insert(tk.END, f"  Type: 0x{resource_type.id:X}\n")
            for resource in resource_type.directory.entries:
                text_widget.insert(tk.END, f"    Name: {resource.name}\n")
                text_widget.insert(tk.END, f"    Offset: {resource.data.struct.OffsetToData}\n")
                text_widget.insert(tk.END, f"    Size: {resource.data.struct.Size}\n")
            text_widget.insert(tk.END, "\n")

    if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
        text_widget.insert(tk.END, "Debug Information:\n", "bold")
        for debug in pe.DIRECTORY_ENTRY_DEBUG:
            text_widget.insert(tk.END, f"  Characteristics: {hex(debug.struct.Characteristics)}\n")
            text_widget.insert(tk.END, f"  TimeDateStamp: {hex(debug.struct.TimeDateStamp)}\n")
            text_widget.insert(tk.END, f"  MajorVersion: {debug.struct.MajorVersion}\n")
            text_widget.insert(tk.END, f"  MinorVersion: {debug.struct.MinorVersion}\n")
            text_widget.insert(tk.END, f"  Type: {hex(debug.struct.Type)}\n")
            text_widget.insert(tk.END, f"  SizeOfData: {debug.struct.SizeOfData}\n")
            text_widget.insert(tk.END, f"  AddressOfRawData: {hex(debug.struct.AddressOfRawData)}\n")
            text_widget.insert(tk.END, f"  PointerToRawData: {hex(debug.struct.PointerToRawData)}\n")
        text_widget.insert(tk.END, "\n")

    if hasattr(pe, 'FileInfo'):
        for file_info in pe.FileInfo:
            if file_info.Key == b'StringFileInfo':
                text_widget.insert(tk.END, "Version Information:\n", "bold")
                for st in file_info.StringTable:
                    for entry in st.entries.items():
                        text_widget.insert(tk.END, f"  {entry[0]}: {entry[1]}\n")
            elif file_info.Key == b'VarFileInfo':
                text_widget.insert(tk.END, "Var Information:\n", "bold")
                for var in file_info.Var:
                    text_widget.insert(tk.END, f"  {var.entry.items()}\n")
        text_widget.insert(tk.END, "\n")

    strings = extract_strings(file_path)
    if strings:
        text_widget.insert(tk.END, "Strings:\n", "bold")
        for string in strings:
            text_widget.insert(tk.END, f"  {string}\n")
        text_widget.insert(tk.END, "\n")

    virus_total_result = check_virus_total(hashes['sha256'])
    text_widget.insert(tk.END, virus_total_result, "bold")

def check_virus_total(sha256_hash):
    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            result = response.json()
            attributes = result['data']['attributes']
            malicious = attributes['last_analysis_stats']['malicious']
            total = sum(attributes['last_analysis_stats'].values())
            percentage = (malicious / total) * 100 if total > 0 else 0
            
            tools_list = "\n".join([engine for engine, details in attributes['last_analysis_results'].items() if details['category'] == 'malicious'])
            tools_list = tools_list if tools_list else "None"
            
            return f"VirusTotal: {malicious}/{total} ({percentage:.2f}%) tools detected this file as malicious.\nTools that detected it as malicious:\n{tools_list}\n"
        else:
            return "VirusTotal: Error retrieving data.\n"
    except Exception as e:
        return f"VirusTotal: An error occurred - {e}\n"

def display_analysis_results(file_path):
    root = tk.Tk()
    root.title("PE File Analyzer")
    root.geometry("600x500")
    root.configure(bg="#f0f0f0")

    title_label = ttk.Label(root, text="PE File Analyzer", font=("Arial", 20), background="#f0f0f0", foreground="#333333")
    title_label.pack(pady=20)

    text_widget = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=60, height=20, font=("Arial", 10))
    text_widget.pack(expand=True, fill=tk.BOTH, padx=20, pady=10)

    analyze_pe(file_path, text_widget)

    root.mainloop()

def select_file():
    file_path = filedialog.askopenfilename(title="Select a PE file", filetypes=(("Executable files", "*.exe"), ("All files", "*.*")))
    if file_path:
        display_analysis_results(file_path)

def create_gui():
    root = tk.Tk()
    root.title("PE File Analyzer")
    root.geometry("600x500")
    root.configure(bg="#f0f0f0")

    title_label = ttk.Label(root, text="PE File Analyzer", font=("Arial", 20), background="#f0f0f0", foreground="#333333")
    title_label.pack(pady=20)

    select_button = ttk.Button(root, text="Select PE File", command=select_file)
    select_button.pack(pady=10)
    image_path = "example.png"
    image = tk.PhotoImage(file=image_path)

    # Create a Label widget to display the image
    image_label = ttk.Label(root, image=image)
    image_label.pack(pady=10)
    root.mainloop()

if __name__ == "__main__":
    create_gui()
