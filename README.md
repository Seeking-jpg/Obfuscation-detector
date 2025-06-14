# Obfuscation-detector

**Obfuscation-detector** is a command-line Python tool designed to analyze Python scripts for signs of obfuscation. It detects and classifies known obfuscators using:

- ✅ Signature-based detection (via regex pattern matching)
- ✅ Entropy analysis
- ✅ Metadata inspection

This tool is ideal for malware analysts, reverse engineers, and developers auditing Python code for security risks.

---

## 🚀 Features

- Detects common Python obfuscators (e.g., PyArmor, Nuitka, pyminifier and random Github obfuscators)
- Calculates and scores entropy to identify obfuscated strings
- Identifies suspicious code constructs, such as dynamic `exec`/`eval` usage
- Classifies obfuscation techniques based on detection results

---

## 🧠 Planned Features

- [ ] Heuristic-based scoring system
- [ ] Decoding of public stealer's (discord token grabber)
- [ ] Detection of encrypted blobs and their potential decoding routines
- [ ] Detection of runtime decryption and unpacking
- [ ] Visual report generation (e.g., HTML or JSON output)
- [ ] Integration with VirusTotal and other public malware analysis APIs
- [ ] Web-based frontend for easier usage
- [ ] PyInstaller/Nuitka stub detection

---

## 💬 Community & Support

Join the community and get support via our Discord server:

👉 **[Join our Discord]([https://discord.gg/your-invite-link](https://discord.gg/PSwV57Xz))**

We welcome feature requests, bug reports, and contributions!

---

## 🛠️ Installation

```bash
git clone https://github.com/Seeking-jpg/Obfuscation-detector.git
cd Obfuscation-detector
pip install -r requirements.txt
