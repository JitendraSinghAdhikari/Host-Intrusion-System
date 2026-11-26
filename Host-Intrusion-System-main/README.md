# Host Intrusion Detection System (HIDS)

A Windows-based **Signature-Based Host Intrusion Detection System (HIDS)** that monitors the file system and process activities for suspicious behavior using YARA rules. It provides a modern web-based GUI and supports real-time alerts, configurable scanning, and process/file quarantine features.

## 🌐 Features

- 🕵️ Real-time **file and process monitoring**
- ⚠️ Detection of malicious patterns via **YARA signatures**
- 📦 **Quarantine** suspicious files
- 🚫 Optional **process termination** for malicious activities
- 🔁 **Periodic scanning** of critical system files
- 🌈 Clean **Web UI** to visualize monitoring, logs, and controls
- ⚙️ Highly **configurable** via `config.ini`
- 📝 Detailed **logging** with rotation support

---

## 🖥️ GUI Overview

The web interface (built using Flask + JS/CSS) allows users to:

- View monitoring status
- See recent suspicious activity logs
- Start/Stop monitoring
- Clear detection logs

## ✅ Test se kya sabit hua aur kya nahi

### Basic file-detection demo

- `test_area` mein rakhi inert test script par YARA file detection aur alert generation verify hua.
- Suspicious test file ko configured local `test_quarantine` folder mein move hote verify kiya.
- Is demo se file scanning aur quarantine workflow sabit hota hai; ise real malware ya production accuracy ka proof na samjhein.

### Extended safe integration checks

- Start/Stop/Clear API responses verify kiye.
- Harmless process argument mein `mimikatz` marker rakhkar process-signature alert verify kiya; koi malware execute nahi hua aur process termination disabled thi.
- Temporary disposable `HKCU` registry test key update karke registry-change alert verify kiya.
- Periodic scan completion/count aur process baseline file save hona verify kiya.

### YARA false-positive sanity check

Run the in-memory sample evaluation from the project folder (samples are not written to disk or executed):

```powershell
.\.venv\Scripts\python.exe eval_yara.py
```

Latest run on the 16 hand-authored samples: **TP=6, FN=0, FP=2, TN=8**; recall **100%**, precision **75%**, false-positive rate **20%**, and accuracy **88%**. The two deliberately included benign weak spots were a Chocolatey-style `iex` + `DownloadString` installer and a game EXE containing “Age of Empires”; both matched broad signature strings.

These numbers describe only this small sanity-check set, not real-world HIDS accuracy or malware-detection coverage. Keep the benign weak-spot cases visible when presenting results; do not report only the 100% recall figure.

### Abhi kya prove nahi hua

- Process/registry/anomaly components ke false-positive rates aur anomaly-detection accuracy ka systematic evaluation abhi nahi hua; YARA file false-positive test sirf upar wale 16 hand-made samples tak limited hai.
- Process signature test marker-based tha; isse real malware detection coverage prove nahi hoti.
- `kill_process` action jaan-boojhkar disabled thi, isliye termination behavior test nahi hua.
- Protected Windows system folders par quarantine test nahi kiya; monitoring test ke liye `test_area` tak limited hai.






---

## 🧱 Project Structure

```plaintext
.
├── hids.py              # Main application logic and API endpoints
├── signatures.py        # YARA rules used for detection
├── config.ini           # Configuration file
├── requirements.txt     # Python dependencies
├── templates/
│   └── index.html       # HTML for the web GUI
├── static/
│   ├── style.css        # Web GUI styling
│   ├── script.js        # Client-side behavior
│   ├── shield.png       # Icon used in GUI
│   └── alert.mp3        # Audio alert for detections
└── hids.log             # Auto-generated log file (after running)
