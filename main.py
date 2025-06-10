import sys
import re
import math
import os
import json

obfuscator_info = {
    "PyArmor": {
        "description": "Commercial Python obfuscator using binary runtime layers.",
        "risk": "High",
        "deobfuscation": "Use unpyarmor or patched pytransform loader.",
        "link to obfuscator": "https://github.com/dashingsoft/pyarmor",
        "notes": "Often used in pirated or malware-packed code."
    },
    "Nuitka": {
        "description": "Python-to-C compiler; output is compiled to binaries.",
        "risk": "Low",
        "deobfuscation": "Requires disassembly or reverse engineering of binary.",
        "notes": "More a compiler than an obfuscator, but can hide logic."
    },
    "Kannadafy": {
        "description": "Uses Kannada characters mapped to binary to obfuscate code.",
        "risk": "Medium",
        "link to obfuscator": "https://github.com/mithun50/Kannadafy",
        "deobfuscation": "Reverse mapping from Kannada characters to bits.",
        "notes": "Rare, but easily identifiable by character set."
    },
    "py-fuscate": {
        "description": "Marshalled and compressed payload wrapper.",
        "risk": "High",
        "deobfuscation": "Use marshal, decompress manually.",
        "link to obfuscator": "https://github.com/ak-alien/Pyencoder",
        "notes": "Often used in loaders and droppers."
    },
    "g0w6y-obfuscator": {
        "description": "Injects redundant imports and utf-8 headers.",
        "risk": "Medium",
        "deobfuscation": "Remove repeated imports, analyze manually.",
        "link to obfuscator": "https://github.com/g0w6y/obfuscator",
        "notes": "More annoying than dangerous, signature-based."
    },
    "Hyperion": {
        "description": "Lambda-heavy, math-redefined obfuscator.",
        "risk": "High",
        "deobfuscation": "Manual analysis or symbolic execution.",
        "link to obfuscator": "https://github.com/billythegoat356/Hyperion",
        "notes": "Very confusing control flow, often malware-related."
    },
    "Berserker": {
        "description": "Obfuscates strings using lambda and byte operations.",
        "risk": "High",
        "deobfuscation": "Trace execution and decode manually.",
        "link to obfuscator": "https://github.com/billythegoat356/Berserker",
        "notes": "Appears small but hides complex behavior."
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
        print("\n=== Obfuscation Detection Result ===")
        if detected:
            print("Detected obfuscation methods/obfuscators:")
            for i, name in enumerate(detected, 1):
                print(f"  {i}. {name}")
        else:
            print("No known obfuscation detected.")

        print("\nWhat would you like to do?")
        print("[1] Show obfuscated variable names")
        print("[2] Show general script info")
        print("[3] View raw source preview")
        print("[4] Run external deobfuscator (placeholder)")
        print("[5] Show obfuscator descriptions")
        print("[0] Exit")

        choice = input("Choose an option: ")

        if choice == "1":
            os.system('cls')
            print("\n[!] Suspicious high-entropy variable names:")
            suspicious = detect_high_entropy_vars(code)
            if not suspicious:
                os.system('cls')
                print("  No suspicious variable names detected.")
            else:
                for var in suspicious:
                    print(f"  - {var}")
        elif choice == "2":
            os.system('cls')
            lines = code.splitlines()
            print("\nGeneral File Info:")
            print(f"  Total lines     : {len(lines)}")
            print(f"  Total characters: {len(code)}")
            imports = sorted(set(re.findall(r'^import (\w+)', code, re.MULTILINE)))
            print(f"  Unique imports  : {', '.join(imports)}")
        elif choice == "3":
            os.system('cls')
            print("\n First 20 lines of source:")
            for i, line in enumerate(code.splitlines()[:20], 1):
                print(f"{i:3}: {line}")
        elif choice == "4":
            os.system('cls')
            print("\n Placeholder for external deobfuscator integration.")
            print("Example: integrate uncompyle6, decompyle3, or a custom unpacker.")
        elif choice == "5":
            os.system('cls')
            print("""
going to add some ascii art in here some day:) 
""""")
            for name in detected:
                info = obfuscator_info.get(name)
                if info:
                    print(f"== {name} ==")
                    print(f"  Description        : {info.get('description', 'N/A')}")
                    print(f"  Risk Level         : {info.get('risk', 'N/A')}")
                    print(f"  Deobfuscation      : {info.get('deobfuscation', 'N/A')}")
                    print(f"  Link to obfuscator : {info.get('deobfuscator Link', "N/A")}")
                    print(f"  Notes              : {info.get('notes', 'N/A')}\n")
                else:
                    print(f"== {name} ==\n  No description available.\n")
        elif choice == "0":
            print("Goodbye!")
            break
        else:
            print("Invalid option. Try again.")


def main():
    print("=== Python Obfuscation Detector ===")
    print("Please drag and drop the Python script you'd like to analyze, then press Enter:")

    filepath = input(">>> ").strip().strip('"')
    

    if not filepath:
        print("[!] No file provided. Exiting.")
        return

    if not os.path.isfile(filepath):
        print("[!] File not found:", filepath)
        return

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        global code
        code = f.read()
    obfuscators = load_obfuscator_patterns()  # still loading patterns from JSON
    detected = detect_obfuscation(code, obfuscators)
    display_menu(detected)

if __name__ == "__main__":
    main()
