import sys
import re
import math
import os
import json
import subprocess
from colorama import init, Fore, Style

init(autoreset=True)

def set_window_size(columns=80, lines=25):
    if os.name == 'nt':
        os.system(f'mode con: cols={columns} lines={lines}')
    else:
        print("Window resizing is only supported on Windows.")

# Example: Set to 80x25

obfuscator_info = {
    "PyArmor": {
        "description": "Commercial Python obfuscator using binary runtime layers.",
        "risk": "High",
        "deobfuscation": "Use unpyarmor or patched pytransform loader.",
        "link to obfuscator": "https://github.com/dashingsoft/pyarmor",
        "notes": "Often used in pirated or malware-packed code.",
        "Public deobfuscator": "False", 
    },
    "Nuitka": {
        "description": "Python-to-C compiler; output is compiled to binaries.",
        "risk": "Low",
        "deobfuscation": "Requires disassembly or reverse engineering of binary.",
        "notes": "More a compiler than an obfuscator, but can hide logic.",
        "Public deobfuscator": "False", 
    },
    "Kannadafy": {
        "description": "Uses Kannada characters mapped to binary to obfuscate code.",
        "risk": "Medium",
        "link to obfuscator": "[https://github.com/mithun50/Kannadafy]",
        "deobfuscation": "Reverse mapping from Kannada characters to bits.",
        "notes": "Rare, but easily identifiable by character set.",
        "Public deobfuscator": "True [https://github.com/Seeking-jpg/Kannadafy-deobfuscator]", 
    },
    "py-fuscate": {
        "description": "Marshalled and compressed payload wrapper.",
        "risk": "High",
        "deobfuscation": "Use marshal, decompress manually.",
        "link to obfuscator": "https://github.com/ak-alien/Pyencoder",
        "notes": "Often used in loaders and droppers.",
        "Public deobfuscator": "False [in development]" 
    },
    "g0w6y-obfuscator": {
        "description": "Injects redundant imports and utf-8 headers.",
        "risk": "Medium",
        "deobfuscation": "Remove repeated imports, analyze manually.",
        "link to obfuscator": "https://github.com/g0w6y/obfuscator",
        "notes": "More annoying than dangerous, signature-based.",
        "Public deobfuscator": "False [in development]" 
    },
    "Hyperion": {
        "description": "Lambda-heavy, math-redefined obfuscator.",
        "risk": "High",
        "deobfuscation": "Manual analysis or symbolic execution.",
        "link to obfuscator": "https://github.com/billythegoat356/Hyperion",
        "notes": "Very confusing control flow, often malware-related.",
        "Public deobfuscator": "True [https://github.com/KhanhNguyen9872/hyperion_deobfuscate]" 
    },
    "Berserker": {
        "description": "Obfuscates strings using lambda and byte operations.",
        "risk": "High",
        "deobfuscation": "Trace execution and decode manually.",
        "link to obfuscator": "https://github.com/billythegoat356/Berserker",
        "notes": "Appears small but hides complex behavior.",
        "Public deobfuscator": "True [https://github.com/KhanhNguyen9872/hyperion_deobfuscate]"
    },
    "Base64 encoded": {
        "description": "Encodes Python code as base64 string.",
        "risk": "Medium",
        "deobfuscation": "Use base64 decode and inspect result.",
        "notes": "Common in simple malware loaders."
    },
    "Hex encoded": {
        "description": "Encodes Python code as hex string.",
        "risk": "Medium",
        "deobfuscation": "Use bytes.fromhex and decode to string.",
        "notes": "Obscures content, easy to reverse."
    },
    "Asterion": {
        "description": "Asterion is a Python obfuscator that uses heavy compression (zlib), base64 encoding, and marshaling of code.",
        "risk": "High",
        "deobfuscation": "Requires manual unpacking of marshal and decompress layers. Use base64 decode > zlib decompress > marshal.loads chain.",
        "link to obfuscator": "https://github.com/Srungot/Asterion-PyObfuscator",
        "notes": "Identifiable by comments and __OBF__ = 'Asterion'. Often used to bundle payloads in a single encoded block."
    },

    "Marshal": {
        "description": "Compiles code objects and embeds them.",
        "risk": "High",
        "deobfuscation": "Use marshal.loads and analyze result.",
        "notes": "Common in loaders and crypters."
    },
    "Zlib compression": {
        "description": "Compresses embedded Python code.",
        "risk": "Medium",
        "deobfuscation": "Decompress and inspect code.",
        "notes": "Used to hide content, often in combination."
    },
    "Runtime code generation": {
        "description": "Dynamic code execution via eval/exec.",
        "risk": "High",
        "deobfuscation": "Manual analysis required.",
        "notes": "Used heavily in malware and scripts."
    },
    "SourceDefender": {
        "description": "Commercial code protector that encrypts Python scripts into .pye files.",
        "risk": "Medium",
        "deobfuscation": "Requires cracking the loader or dumping memory at runtime.",
        "notes": "Used by developers to prevent code leaks; harder to reverse without the loader."
    }
}

def load_obfuscator_patterns(file="patterns.json"):
    try:
        with open(file, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[!] Could not load obfuscation patterns: {e}")
        return {}

def calculate_entropy(text):
    if not text:
        return 0
    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    return -sum([p * math.log(p) / math.log(2.0) for p in prob])

def detect_high_entropy_vars(code, threshold=4.0):
    variables = re.findall(r"\b([a-zA-Z_][a-zA-Z0-9_]{5,})\b", code)
    return [var for var in variables if calculate_entropy(var) >= threshold]

def detect_obfuscation(code, patterns):
    detected = []
    for name, regexes in patterns.items():
        for pattern in regexes:
            if re.search(pattern, code):
                detected.append(name)
                break
    if len(detect_high_entropy_vars(code)) > 5:
        detected.append("High entropy variable names (likely obfuscated)")
    return list(set(detected))

def display_menu(detected):
    while True:
        print(Fore.CYAN + "\n                       === Obfuscation Detection Result ===")
        if detected:
            print(Fore.CYAN + "")
            for i, name in enumerate(detected, 1):
                print((Fore.MAGENTA +"detected: ") + f"  {i}. {name}")
        else:
            print(Fore.RED +"No known obfuscation detected.")

        print(Fore.BLUE + "\nWhat would you like to do?")
        print(Fore.BLUE + "[1] Show obfuscated variable names")
        print(Fore.BLUE + "[2] Show general script info")
        print(Fore.BLUE + "[3] View raw source preview")
        print(Fore.BLUE + "[4] Run external deobfuscator (placeholder)")
        print(Fore.BLUE + "[5] Show obfuscator descriptions")
        print(Fore.BLUE + "[0] Exit")

        choice = input("Choose an option: ")

        if choice == "1":
            os.system('cls' if os.name == 'nt' else 'clear')
            print("\n[!] Suspicious high-entropy variable names:")
            suspicious = detect_high_entropy_vars(code)
            if not suspicious:
                print("  No suspicious variable names detected.")
            else:
                for var in suspicious:
                    print(f"  - {var}")
        elif choice == "2":
            os.system('cls' if os.name == 'nt' else 'clear')
            lines = code.splitlines()
            print("\nGeneral File Info:")
            print(f"  Total lines     : {len(lines)}")
            print(f"  Total characters: {len(code)}")
            imports = sorted(set(re.findall(r'^import (\w+)', code, re.MULTILINE)))
            print(f"  Unique imports  : {', '.join(imports)}")
        elif choice == "3":
            os.system('cls' if os.name == 'nt' else 'clear')
            print("\n First 20 lines of source:")
            for i, line in enumerate(code.splitlines()[:20], 1):
                print(f"{i:3}: {line}")
        elif choice == "4":
            os.system('cls' if os.name == 'nt' else 'clear')
            print("\n Placeholder for external deobfuscator integration.")
            print("Example: integrate uncompyle6, decompyle3, or a custom unpacker.")
        elif choice == "5":
            os.system('cls' if os.name == 'nt' else 'clear')
            print("Going to add some ASCII art here some day :) \n")
            for name in detected:
                info = obfuscator_info.get(name)
                if info:
                    print(f"== {name} ==")
                    print(f"  Description         : {info.get('description', 'N/A')}")
                    print(f"  Risk Level          : {info.get('risk', 'N/A')}")
                    print(f"  Deobfuscation       : {info.get('deobfuscation', 'N/A')}")
                    print(f"  Link to obfuscator  : {info.get('link to obfuscator', 'N/A')}")
                    print(f"  Notes               : {info.get('notes', 'N/A')}")
                    print(f"  Public deobfuscator : {info.get('Public deobfuscator', 'N/A')}\n")
                else:
                    print(f"== {name} ==\n  No description available.\n")
        elif choice == "0":
            print("Goodbye!")
            break
        else:
            print("Invalid option. Try again.")

def scan_for_stealer(filepath):
    print("place holder")

def analyze_for_obfuscation(filepath):
    global code
    set_window_size(80, 25)
    if not os.path.isfile(filepath):
        print("[!] File not found:", filepath)
        return

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        code = f.read()

    obfuscators = load_obfuscator_patterns()  # Load patterns from JSON file
    detected = detect_obfuscation(code, obfuscators)
    display_menu(detected)

def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    set_window_size(45, 20)
    print(Fore.CYAN + "          ==== Python Analyzer ====\n")
    
    # Accept file path via argument or drag & drop
    if len(sys.argv) > 1:
        filepath = sys.argv[1]
    else:
        filepath = input(Fore.RED +"                   ↓↓↓↓↓↓↓ ").strip('"')

    if not os.path.isfile(filepath):
        print("[!] Invalid file path.")
        return

    print("\nWhat kind of analysis do you want to perform?")
    print("[1] Detect Discord token stealer (soon)")
    print("[2] Analyze for Python obfuscation")
    choice = input("Enter 1 or 2: ").strip()

    if choice == '1':
        os.system('cls' if os.name == 'nt' else 'clear')
        analyze_for_obfuscation(filepath)     
    elif choice == '2':
        os.system('cls' if os.name == 'nt' else 'clear')
        analyze_for_obfuscation(filepath)       
    else:
        print("Invalid choice, exiting.")

if __name__ == "__main__":
    main()
