import os
import sys
import time
import json
import shutil
import threading
import uuid
import hashlib
import zipfile
import xml.etree.ElementTree as ET
import winreg
import win32api
import win32con
import win32security
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import yara
import configparser
import logging
from logging.handlers import RotatingFileHandler
import re
from collections import defaultdict
from flask import Flask, jsonify, render_template
from signatures import FILE_SIGNATURES, PROCESS_SIGNATURES, KNOWN_MALICIOUS_HASHES

# Configure logging
log_handler = RotatingFileHandler('hids.log', maxBytes=1_000_000, backupCount=3)
logging.basicConfig(
    handlers=[log_handler],
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

app = Flask(__name__, template_folder='templates', static_folder='static')

# Windows API Process Monitoring
class ProcessMonitor:
    def __init__(self):
        self.last_processes = set()

    def get_process_list(self):
        """Return process IDs visible to the current user."""
        return {proc.pid for proc in psutil.process_iter()}

    def get_process_name(self, pid):
        if not pid:
            return None
        try:
            return psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None

    def get_process_info(self, pid):
        try:
            process = psutil.Process(pid)
            info = process.as_dict(attrs=['name', 'exe', 'ppid', 'cmdline'])
            return {
                'name': info.get('name') or '',
                'path': info.get('exe'),
                'parent_pid': info.get('ppid'),
                'command_line': ' '.join(info.get('cmdline') or [])
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None

    def detect_new_processes(self):
        current_processes = self.get_process_list()
        new_processes = current_processes - self.last_processes
        self.last_processes = current_processes
        return new_processes

    def get_parent_pid(self, pid):
        try:
            return psutil.Process(pid).ppid()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None

# Enable SeDebugPrivilege
def enable_privilege(privilege_name):
    try:
        flags = win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY
        token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), flags)
        privilege_id = win32security.LookupPrivilegeValue(None, privilege_name)
        win32security.AdjustTokenPrivileges(token, False, [(privilege_id, win32con.SE_PRIVILEGE_ENABLED)])
        logging.info(f"Privilege {privilege_name} enabled successfully")
        return True
    except Exception as e:
        logging.error(f"Failed to enable privilege {privilege_name}: {str(e)}")
        return False

# YARA rules
yara_rules = r"""
import "pe"

rule malicious_script {
    meta:
        description = "Detects malicious PowerShell patterns"
        severity = "high"
    strings:
        $ps1 = "powershell" nocase
        $iex1 = /Invoke-Expression\s+\(.*DownloadString/ nocase
        $iex2 = /iex\s+\(.*DownloadString/ nocase
        $webclient = /New-Object\s+Net\.WebClient.*Download/ nocase
        $hidden = /Start-Process\s+-WindowStyle\s+Hidden/ nocase
        $base64 = /FromBase64String\s*\(/ nocase
    condition:
        $ps1 and (
            ($iex1 or $iex2) or
            ($webclient and $hidden) or
            ($base64 and filesize < 50KB)
        )
}

rule suspicious_executable {
    meta:
        description = "Detects suspicious executables"
        severity = "critical"
    strings:
        $mz = "MZ"
        $s1 = "mimikatz" nocase wide
        $s2 = "cobaltstrike" nocase wide
        $s3 = "empire" nocase wide
        $s4 = /powershell.*-nop.*-w\s+hidden/ nocase
    condition:
        $mz at 0 and (
            any of ($s*) or
            (pe.imports("Advapi32.dll", "OpenProcessToken") and
             pe.imports("Advapi32.dll", "AdjustTokenPrivileges"))
        )
}

rule temp_executable {
    meta:
        description = "Detects executables in temp folders"
        severity = "medium"
    strings:
        $temp1 = /\\Temp\\/ nocase
        $temp2 = /\\Temporary\\/ nocase
        $temp3 = /AppData\\Local\\Temp\\/ nocase
    condition:
        uint32(0) == 0x5A4D and
        any of ($temp*) and
        filesize < 10MB
}
"""

class RegistryMonitor:
    def __init__(self, hids):
        self.hids = hids
        raw_keys = hids.config.get('ANOMALY', 'suspicious_registry_keys', fallback='')
        self.suspicious_keys = [value.strip() for value in raw_keys.split(',') if value.strip()]

    def _registry_keys(self):
        roots = {
            'HKLM': winreg.HKEY_LOCAL_MACHINE,
            'HKEY_LOCAL_MACHINE': winreg.HKEY_LOCAL_MACHINE,
            'HKCU': winreg.HKEY_CURRENT_USER,
            'HKEY_CURRENT_USER': winreg.HKEY_CURRENT_USER,
            'HKU': winreg.HKEY_USERS,
            'HKEY_USERS': winreg.HKEY_USERS
        }
        result = []
        for value in self.suspicious_keys:
            hive, separator, subkey = value.partition('\\')
            if separator and hive.upper() in roots:
                result.append((value, roots[hive.upper()], subkey))
            else:
                logging.warning('Ignoring unsupported registry path: %s', value)
        return result

    @staticmethod
    def _last_write_time(root, subkey):
        try:
            with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ) as key:
                return winreg.QueryInfoKey(key)[2]
        except FileNotFoundError:
            return None

    def monitor_registry(self):
        registry_keys = self._registry_keys()
        last_write = {}
        for name, root, subkey in registry_keys:
            try:
                last_write[name] = self._last_write_time(root, subkey)
            except OSError as exc:
                last_write[name] = None
                logging.warning('Initial registry check failed for %s: %s', name, exc)
        logging.info('Registry monitor started (%d configured keys)', len(registry_keys))
        interval = int(self.hids.config.get('MONITORING', 'registry_check_interval', fallback=5))
        while self.hids.monitoring_active and not self.hids.stop_event.is_set():
            for name, root, subkey in registry_keys:
                try:
                    current = self._last_write_time(root, subkey)
                    previous = last_write.get(name)
                    if current is not None and previous is not None and current != previous:
                        self.hids.trigger_alert(f'SUSPICIOUS REGISTRY MODIFICATION: {name}')
                    last_write[name] = current
                except OSError as exc:
                    logging.warning('Registry check failed for %s: %s', name, exc)
            self.hids.stop_event.wait(interval)

class HIDS:
    def __init__(self):
        self.config = configparser.ConfigParser()
        self.config.read('config.ini')
        self.monitoring_active = False
        enable_privilege(win32con.SE_DEBUG_NAME)
        try:
            self.rules = yara.compile(source=FILE_SIGNATURES)
            self.process_rules = yara.compile(source=PROCESS_SIGNATURES)
            logging.info('File and process YARA signatures compiled successfully')
        except yara.Error as exc:
            logging.error('YARA signature compilation error: %s', exc)
            raise
        self.suspicious_activities = []
        self.process_monitor = ProcessMonitor()
        self.last_alert_time = {}
        self.whitelist = self.load_whitelist()
        self.observer = None
        self.background_threads = []
        self.stop_event = threading.Event()
        self.last_periodic_scan = None
        self.last_periodic_scan_files = 0
        self.periodic_scan_count = 0
        self.registry_monitor = RegistryMonitor(self)
        self.anomaly_detection = self.config.getboolean('MONITORING', 'anomaly_detection', fallback=True)
        self.learning_duration = int(self.config.get('ANOMALY', 'learning_duration', fallback=3600))
        self.baseline_path = self.config.get('PATHS', 'baseline_file', fallback='hids_baseline.json')
        self.behavior_baseline = {'process_tree': defaultdict(int)}
        self.learning_mode = True
        self.load_baseline()

    def load_baseline(self):
        try:
            with open(self.baseline_path, 'r', encoding='utf-8') as baseline_file:
                stored = json.load(baseline_file)
            self.behavior_baseline['process_tree'].update(stored.get('process_tree', {}))
            self.learning_mode = not bool(self.behavior_baseline['process_tree'])
            logging.info('Loaded process baseline (%d relationships)', len(self.behavior_baseline['process_tree']))
        except FileNotFoundError:
            logging.info('No saved process baseline found; it will be initialized on monitoring start')
        except (OSError, ValueError) as exc:
            logging.warning('Could not load process baseline: %s', exc)

    def save_baseline(self):
        directory = os.path.dirname(os.path.abspath(self.baseline_path))
        os.makedirs(directory, exist_ok=True)
        temporary_path = f'{self.baseline_path}.{uuid.uuid4().hex}.tmp'
        with open(temporary_path, 'w', encoding='utf-8') as baseline_file:
            json.dump({'process_tree': dict(self.behavior_baseline['process_tree'])}, baseline_file, indent=2)
        os.replace(temporary_path, self.baseline_path)
        logging.info('Saved process baseline (%d relationships)', len(self.behavior_baseline['process_tree']))

    def build_baseline(self):
        logging.info('Building behavior baseline for anomaly detection...')
        start_time = time.time()
        while time.time() - start_time < self.learning_duration:
            for pid in self.process_monitor.get_process_list():
                info = self.process_monitor.get_process_info(pid)
                if not info:
                    continue
                parent_name = self.process_monitor.get_process_name(info['parent_pid']) or 'unknown'
                process_key = f"{parent_name}->{info['name']}"
                self.behavior_baseline['process_tree'][process_key] += 1
            time.sleep(5)
        self.learning_mode = False
        self.save_baseline()
        logging.info('Baseline established with %d process relationships', len(self.behavior_baseline['process_tree']))

    def load_whitelist(self):
        whitelist = {
            'paths': [
                r'C:\\Windows\\System32\\DriverStore\\',
                r'C:\\Windows\\Temp\\',
                r'AppData\\Local\\Temp\\',
                r'\\$Recycle.Bin\\',
                r'\\AMD\\EeuDumps\\',
                r'\\Microsoft\\Edge\\User Data\\',
                r'\\Spotify\\Users\\'
            ],
            'processes': [
                'svchost.exe',
                'explorer.exe',
                'notepad.exe',
                'chrome.exe',
                'msedge.exe',
                'winlogon.exe'
            ],
            'extensions': ['.exe', '.dll', '.ps1', '.vbs', '.js', '.bat', '.cmd']
        }
        if self.config.has_option('FILTERS', 'whitelisted_paths'):
            whitelist['paths'].extend(
                [x.strip() for x in self.config.get('FILTERS', 'whitelisted_paths').split(';')]
            )
        if self.config.has_option('FILTERS', 'whitelisted_processes'):
            whitelist['processes'].extend(
                [x.strip() for x in self.config.get('FILTERS', 'whitelisted_processes').split(',')]
            )
        if self.config.has_option('FILTERS', 'scan_extensions'):
            whitelist['extensions'] = [
                x.strip() for x in self.config.get('FILTERS', 'scan_extensions').split(',')
            ]
        return whitelist

    def is_whitelisted(self, path_or_name):
        if not path_or_name:
            return False
        path_or_name = path_or_name.lower()
        if any(re.search(rf'\\{p.lower()}$', path_or_name) or
               path_or_name.endswith(p.lower()) for p in self.whitelist['processes']):
            return True
        if any(p.lower() in path_or_name for p in self.whitelist['paths']):
            return True
        return False

    def should_scan_file(self, file_path):
        if not file_path:
            return False
        normalized_path = os.path.abspath(file_path).lower()
        quarantine_path = os.path.abspath(self.config.get(
            'PATHS', 'quarantine_dir', fallback='quarantine'
        )).lower()
        try:
            if os.path.commonpath([normalized_path, quarantine_path]) == quarantine_path:
                return False
        except ValueError:
            pass
        if self.is_whitelisted(normalized_path):
            return False
        if not any(normalized_path.endswith(ext.lower()) for ext in self.whitelist['extensions']):
            return False
        last_alert = self.last_alert_time.get(normalized_path)
        return last_alert is None or time.time() - last_alert >= 60

    def start_monitoring(self):
        if self.monitoring_active:
            return False
        self.background_threads = [thread for thread in self.background_threads if thread.is_alive()]
        for thread in self.background_threads:
            thread.join(timeout=2)
        self.background_threads = []
        self.stop_event.clear()
        self.monitoring_active = True
        logging.info('Starting HIDS monitoring')
        if self.anomaly_detection and self.learning_mode:
            self.capture_baseline_snapshot()
        if self.config.getboolean('MONITORING', 'filesystem', fallback=True):
            self.start_file_monitor()
        if self.config.getboolean('MONITORING', 'processes', fallback=True):
            self.start_api_process_monitor()
        if self.config.getboolean('MONITORING', 'periodic_scans', fallback=True):
            self.start_periodic_scans()
        if self.config.getboolean('MONITORING', 'registry', fallback=False):
            self._start_background_thread(self.registry_monitor.monitor_registry, 'RegistryMonitor')
        return True

    def capture_baseline_snapshot(self):
        """Seed and persist a baseline from currently running process relationships."""
        for pid in self.process_monitor.get_process_list():
            info = self.process_monitor.get_process_info(pid)
            if not info or not info['name']:
                continue
            parent_name = self.process_monitor.get_process_name(info['parent_pid']) or 'unknown'
            self.behavior_baseline['process_tree'][f"{parent_name}->{info['name']}"] += 1
        self.learning_mode = False
        try:
            self.save_baseline()
        except OSError as exc:
            logging.error('Unable to persist process baseline: %s', exc)

    def _start_background_thread(self, target, name):
        thread = threading.Thread(target=target, daemon=True, name=name)
        thread.start()
        self.background_threads.append(thread)
        return thread

    def stop_monitoring(self):
        if not self.monitoring_active:
            return False
        self.monitoring_active = False
        self.stop_event.set()
        logging.info('Stopping HIDS monitoring')
        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=5)
            self.observer = None
        for thread in self.background_threads:
            thread.join(timeout=2)
        return True

    def clear_logs(self):
        self.suspicious_activities.clear()
        logging.info('Cleared suspicious activities log')
        return True

    def start_file_monitor(self):
        paths = [value.strip() for value in self.config.get(
            'PATHS', 'watch_paths', fallback='C:\\Windows\\System32;C:\\Windows\\SysWOW64'
        ).split(';') if value.strip()]
        event_handler = FileSystemEventHandler()
        event_handler.on_modified = self.on_file_modified
        event_handler.on_created = self.on_file_created
        observer = Observer()
        scheduled = 0
        quarantine_path = os.path.abspath(self.config.get('PATHS', 'quarantine_dir', fallback='quarantine'))
        for path in paths:
            if not os.path.isdir(path):
                logging.warning('Watch path is missing or not a directory: %s', path)
                continue
            if os.path.commonpath([os.path.abspath(path), quarantine_path]) == os.path.abspath(path):
                logging.warning('Skipping watch path that contains quarantine: %s', path)
                continue
            try:
                observer.schedule(event_handler, path, recursive=True)
                scheduled += 1
                logging.info('Monitoring path: %s', path)
            except (OSError, ValueError) as exc:
                logging.error('Failed to monitor path %s: %s', path, exc)
        if not scheduled:
            observer.stop()
            logging.warning('File monitoring not started: no valid watch paths')
            return False
        try:
            observer.start()
            self.observer = observer
            logging.info('File system monitoring started')
            return True
        except RuntimeError as exc:
            logging.error('Failed to start file monitor: %s', exc)
            return False

    def on_file_modified(self, event):
        try:
            if not event.is_directory and self.should_scan_file(event.src_path):
                logging.debug('Scanning modified file: %s', event.src_path)
                self.analyze_file(event.src_path, 'modified')
        except Exception as exc:
            logging.error('Error in on_file_modified: %s', exc)

    def on_file_created(self, event):
        try:
            if not event.is_directory and self.should_scan_file(event.src_path):
                logging.debug('Scanning created file: %s', event.src_path)
                self.analyze_file(event.src_path, 'created')
        except Exception as exc:
            logging.error('Error in on_file_created: %s', exc)

    def start_api_process_monitor(self):
        interval = max(1, int(self.config.get('MONITORING', 'process_check_interval', fallback=5)))
        self.process_monitor.last_processes = self.process_monitor.get_process_list()
        logging.info('Process polling monitor started (interval=%ss)', interval)

        def poll_processes():
            while self.monitoring_active and not self.stop_event.is_set():
                try:
                    for pid in self.process_monitor.detect_new_processes():
                        info = self.process_monitor.get_process_info(pid)
                        if info and not self.is_whitelisted(info['name']):
                            self.analyze_process(
                                info['name'], pid, info['path'], info['command_line']
                            )
                except Exception as exc:
                    logging.error('Process monitor error: %s', exc)
                self.stop_event.wait(interval)

        return self._start_background_thread(poll_processes, 'ProcessMonitor')

    def analyze_process(self, name, pid, path, command_line=''):
        try:
            process_data = f'{name} {path or ""} {command_line or ""}'.encode('utf-8', errors='ignore')
            matches = self.process_rules.match(data=process_data)
            risk_factors = []
            if matches:
                risk_factors.append('malicious process')
            if self.anomaly_detection and not self.learning_mode:
                extra_risk = self.detect_process_anomalies(name, pid, path)
                risk_factors.extend(extra_risk)
            zero_day = self.detect_zero_day_behavior(name=name, pid=pid, path=path, command_line=command_line)
            risk_factors.extend(zero_day)
            if matches or risk_factors:
                alert_details = []
                if matches:
                    alert_details.append(f"Matches: {', '.join(str(match) for match in matches)}")
                if zero_day:
                    alert_details.append(f"Zero-day heuristics: {', '.join(zero_day)}")
                if risk_factors:
                    alert_details.append(f"risk_factors: {', '.join(dict.fromkeys(risk_factors))}")
                alert_msg = f"SUSPICIOUS PROCESS: {name} (PID: {pid}) - {' | '.join(alert_details)}"
                action_taken = 'Detected'
                if self.config.getboolean('RESPONSE', 'kill_process', fallback=False):
                    action_taken = 'Terminated' if self.terminate_process(pid) else 'Detection only; termination failed'
                self.trigger_alert(
                    alert_msg,
                    risk_factors,
                    process_name=name,
                    pid=pid,
                    parent_pid=self.process_monitor.get_parent_pid(pid),
                    process_path=path,
                    command_line=command_line,
                    yara_rules=[str(match) for match in matches],
                    action_taken=action_taken,
                    alert_type='Process',
                )
        except Exception as exc:
            logging.error('Error analyzing process %s: %s', name, exc)

    def detect_process_anomalies(self, name, pid, path):
        findings = []
        parent_pid = self.process_monitor.get_parent_pid(pid)
        parent_name = self.process_monitor.get_process_name(parent_pid)
        process_key = f"{parent_name}->{name}"
        # Process tree anomaly
        if not self.behavior_baseline['process_tree'].get(process_key, 0):
            findings.append('suspicious process tree')
        # Temporal anomaly
        current_hour = time.localtime().tm_hour
        late_hours = [int(x) for x in self.config.get('ANOMALY', 'late_night_hours', fallback="23,0,1,2,3,4,5").split(',')]
        if current_hour in late_hours:
            findings.append('late-night process')
        return findings

    def classify_severity(self, score):
        if score <= 29:
            return 'Low'
        if score <= 59:
            return 'Medium'
        if score <= 79:
            return 'High'
        return 'Critical'

    def calculate_risk_score(self, factors):
        factor_weights = {
            'APK detected': 10,
            'suspicious Android permission': 20,
            'embedded APK indicator': 25,
            'suspicious persistence': 25,
            'unknown executable': 20,
            'suspicious script behavior': 18,
            'malicious signature': 45,
            'known malicious hash': 30,
            'suspicious PE/loader': 25,
            'suspicious process tree': 18,
            'late-night process': 12,
            'suspicious command line': 15,
            'malicious process': 35,
        }
        score = 0
        for factor in set(factors or []):
            score += factor_weights.get(factor, 10)
        return max(0, min(100, score))

    def trigger_alert(
        self, message, risk_factors=None, process_name=None, pid=None, parent_pid=None,
        process_path=None, command_line=None, yara_rules=None, action_taken='Detected',
        alert_type='Info', details=None
    ):
        score = self.calculate_risk_score(risk_factors or [])
        severity = self.classify_severity(score)
        log_message = f"{message} [Risk: {score}/100 ({severity})]"
        logging.warning(log_message)
        self.suspicious_activities.append({
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'message': log_message,
            'risk_score': score,
            'severity': severity,
            'alert_type': alert_type,
            'process_name': process_name or '',
            'pid': pid,
            'parent_pid': parent_pid,
            'process_path': process_path or '',
            'command_line': command_line or '',
            'yara_rules': yara_rules or [],
            'action_taken': action_taken,
            'details': details or {},
        })

    def detect_zero_day_behavior(self, name=None, pid=None, path=None, command_line=''):
        findings = []
        lower_name = (name or '').lower()
        lower_path = (path or '').lower()
        lower_command = (command_line or '').lower()

        suspicious_tokens = [
            'powershell', 'rundll32', 'regsvr32', 'mshta', 'certutil', 'bitsadmin',
            'wscript', 'cscript', 'cmd.exe /c', '-nop', '-enc', 'downloadstring',
            'invoke-webrequest', 'http://', 'https://', '.onion', 'start-process',
            'bypass', 'hidden', 'frombase64string'
        ]
        if lower_command and any(token in lower_command for token in suspicious_tokens):
            findings.append('suspicious command line')

        if lower_name and lower_name.endswith(('.tmp', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.dll', '.exe')):
            if not lower_name.startswith(('explorer', 'chrome', 'msedge', 'svchost', 'notepad')):
                findings.append('unknown executable')

        persistence_markers = [
            r'\\startup', r'\\start menu\\programs\\startup', r'\\runonce', r'\\run',
            'startup folder', 'autorun', 'runonce', 'currentversion\\run', 'run key'
        ]
        if any(marker in lower_path for marker in ['\\startup', '\\runonce', '\\run', 'currentversion\\run', 'startup folder']):
            findings.append('suspicious persistence')

        if re.search(r'(\\appdata\\.*(temp|roaming|local)\\|\\windows\\temp\\)', lower_path):
            if lower_name.endswith(('.exe', '.dll', '.ps1', '.js', '.vbs', '.bat', '.cmd')):
                findings.append('suspicious persistence')

        if any(token in lower_command for token in ['http://', 'https://', '.onion']) and any(token in lower_command for token in ['powershell', 'mshta', 'certutil', 'bitsadmin', 'curl', 'wget']):
            findings.append('abnormal outbound connection')

        try:
            for conn in psutil.net_connections(kind='inet'):
                if pid is not None and conn.pid != pid:
                    continue
                if getattr(conn, 'raddr', None) and getattr(conn.raddr, 'ip', None):
                    remote_ip = conn.raddr.ip
                    if remote_ip not in ('127.0.0.1', '::1', '') and remote_ip != 'localhost':
                        findings.append('abnormal outbound connection')
                        break
        except (psutil.Error, OSError):
            pass

        return list(dict.fromkeys(findings))

    def detect_zero_day_file_behavior(self, file_path):
        findings = []
        lower_path = (file_path or '').lower()
        lower_name = os.path.basename(file_path).lower() if file_path else ''

        if any(marker in lower_path for marker in ['\\startup', '\\runonce', '\\run', 'currentversion\\run', 'startup folder']):
            findings.append('suspicious persistence')
        if any(marker in lower_path for marker in ['\\appdata\\local\\temp\\', '\\appdata\\roaming\\', '\\windows\\temp\\']):
            if lower_name.endswith(('.exe', '.dll', '.ps1', '.js', '.vbs', '.bat', '.cmd', '.scr')):
                findings.append('suspicious persistence')
        if lower_name.endswith(('.ps1', '.bat', '.cmd', '.js', '.vbs', '.scr')) and 'temp' in lower_path:
            findings.append('suspicious script behavior')
        if lower_name.endswith(('.exe', '.dll')) and any(marker in lower_path for marker in ['temp', 'download', 'cache']):
            findings.append('unknown executable')
        return list(dict.fromkeys(findings))

    def compute_sha256(self, file_path):
        digest = hashlib.sha256()
        with open(file_path, 'rb') as handle:
            while True:
                chunk = handle.read(65536)
                if not chunk:
                    break
                digest.update(chunk)
        return digest.hexdigest()

    def detect_custom_indicators(self, file_path):
        indicators = []
        risk_factors = []

        try:
            file_hash = self.compute_sha256(file_path).lower()
            configured_hashes = [
                value.strip().lower() for value in self.config.get(
                    'INDICATORS', 'known_malicious_hashes', fallback=''
                ).split(',') if value.strip()
            ]
            for known_hash in sorted(KNOWN_MALICIOUS_HASHES.union(set(configured_hashes))):
                if file_hash == known_hash.lower():
                    indicators.append(f"known malicious SHA256 hash: {file_hash}")
                    risk_factors.append('known malicious hash')
        except OSError as exc:
            logging.warning('Unable to compute hash for %s: %s', file_path, exc)

        try:
            with open(file_path, 'rb') as handle:
                sample = handle.read(4096)
            sample_text = sample.decode('latin-1', errors='ignore').lower()
            configured_markers = [
                value.strip().lower() for value in self.config.get(
                    'INDICATORS', 'suspicious_markers', fallback=''
                ).split(',') if value.strip()
            ]
            suspicious_markers = [
                'frombase64string', 'invoke-expression', 'iex', 'rundll32', 'regsvr32',
                'mshta', 'certutil', 'bitsadmin', 'wscript.shell', 'powershell',
                'virtualalloc', 'writeprocessmemory', 'createremotethread', 'urldownloadtofile',
                'internetopena', 'amsi', 'commandline', 'winexec', 'schtasks'
            ] + configured_markers
            matches = [marker for marker in dict.fromkeys(suspicious_markers) if marker in sample_text]
            if matches:
                indicators.append(f"suspicious script or loader markers: {', '.join(matches[:6])}")
                risk_factors.append('suspicious script behavior')

            if sample.startswith(b'MZ') and any(marker in sample_text for marker in [
                'virtualalloc', 'writeprocessmemory', 'createremotethread', 'urldownloadtofile',
                'internetopena', 'winexec'
            ]):
                indicators.append('suspicious PE header or import table')
                risk_factors.append('suspicious PE/loader')
        except OSError as exc:
            logging.warning('Unable to inspect file header for %s: %s', file_path, exc)

        return indicators, risk_factors

    def detect_apk_file(self, file_path):
        if not file_path or not file_path.lower().endswith('.apk'):
            return None

        apk_info = {
            'package': None,
            'permissions': [],
            'suspicious_permissions': [],
            'embedded_indicators': [],
            'risk_factors': ['APK detected'],
        }

        suspicious_permissions = {
            'android.permission.SEND_SMS',
            'android.permission.RECEIVE_SMS',
            'android.permission.READ_SMS',
            'android.permission.CALL_PHONE',
            'android.permission.WRITE_CONTACTS',
            'android.permission.READ_CONTACTS',
            'android.permission.INSTALL_PACKAGES',
            'android.permission.REQUEST_INSTALL_PACKAGES',
            'android.permission.DELETE_PACKAGES',
            'android.permission.READ_LOGS',
            'android.permission.SYSTEM_ALERT_WINDOW',
            'android.permission.BIND_DEVICE_ADMIN',
            'android.permission.READ_CALL_LOG',
            'android.permission.RECORD_AUDIO',
            'android.permission.CAMERA',
            'android.permission.ACCESS_FINE_LOCATION',
        }

        try:
            with zipfile.ZipFile(file_path) as apk_zip:
                names = set(apk_zip.namelist())
                if 'AndroidManifest.xml' not in names:
                    return None

                manifest = apk_zip.read('AndroidManifest.xml')
                root = ET.fromstring(manifest)
                apk_info['package'] = root.attrib.get('package')
                for element in root.iter():
                    perm = element.attrib.get('{http://schemas.android.com/apk/res/android}name')
                    if perm:
                        apk_info['permissions'].append(perm)

                apk_info['suspicious_permissions'] = sorted({
                    perm for perm in apk_info['permissions'] if perm in suspicious_permissions
                })
                if apk_info['suspicious_permissions']:
                    apk_info['risk_factors'].append('suspicious Android permission')

                for member_name in sorted(names):
                    if not member_name.lower().endswith(('.xml', '.txt', '.smali', '.dex')):
                        continue
                    try:
                        data = apk_zip.read(member_name)
                    except (KeyError, OSError, zipfile.BadZipFile):
                        continue
                    text = data.decode('utf-8', 'ignore').lower()
                    markers = [
                        'runtime.getruntime().exec', 'dexclassloader', 'android.intent.action.boot_completed',
                        'su', 'chmod', 'request_install_packages', 'send_sms', 'read_sms', 'write_sms',
                        'startservice', 'broadcastreceiver', 'android.permission.system_alert_window'
                    ]
                    for marker in markers:
                        if marker in text and marker not in apk_info['embedded_indicators']:
                            apk_info['embedded_indicators'].append(marker)
                if apk_info['embedded_indicators']:
                    apk_info['risk_factors'].append('embedded APK indicator')

                file_hash = self.compute_sha256(file_path).lower()
                if file_hash in {h.lower() for h in KNOWN_MALICIOUS_HASHES}:
                    apk_info['risk_factors'].append('known malicious hash')

                risk_score = self.calculate_risk_score(apk_info['risk_factors'])
                severity = self.classify_severity(risk_score)
                apk_info['score'] = risk_score
                apk_info['severity'] = severity
                apk_info['hash'] = file_hash
                return apk_info
        except (OSError, ValueError, zipfile.BadZipFile, ET.ParseError) as exc:
            logging.warning('Unable to inspect APK metadata for %s: %s', file_path, exc)
        return None

    def analyze_file(self, file_path, action):
        try:
            matches = self.rules.match(filepath=file_path)
            custom_indicators, risk_factors = self.detect_custom_indicators(file_path)
            if matches:
                risk_factors.append('malicious signature')
            zero_day_file = self.detect_zero_day_file_behavior(file_path)
            risk_factors.extend(zero_day_file)
            apk_info = self.detect_apk_file(file_path)
            if apk_info:
                risk_factors.extend(apk_info.get('risk_factors', []))
            if not matches and not custom_indicators and not zero_day_file and not apk_info:
                return []

            normalized_path = os.path.abspath(file_path).lower()
            self.last_alert_time[normalized_path] = time.time()
            details = []
            if matches:
                details.append(f"YARA: {', '.join(str(match) for match in matches)}")
            if custom_indicators:
                details.append(f"Indicators: {'; '.join(custom_indicators)}")
            if zero_day_file:
                details.append(f"Zero-day heuristics: {', '.join(zero_day_file)}")
            if apk_info:
                details.append(
                    f"APK: package={apk_info.get('package') or 'unknown'}; permissions={', '.join(apk_info.get('permissions', [])[:8]) or 'none'}; risk={apk_info.get('score', 0)}/100 ({apk_info.get('severity', 'Low')})"
                )
            risk_factors = list(dict.fromkeys(risk_factors))
            alert_msg = f"SUSPICIOUS FILE {action}: {file_path} - {' | '.join(details)}"
            action_taken = 'Detected'
            if self.config.getboolean('RESPONSE', 'quarantine', fallback=False):
                action_taken = 'Quarantined' if self.quarantine_file(file_path) else 'Detection only; quarantine failed'
            self.trigger_alert(
                alert_msg,
                risk_factors,
                process_name=os.path.basename(file_path),
                process_path=os.path.abspath(file_path),
                yara_rules=[str(match) for match in matches],
                action_taken=action_taken,
                alert_type='File',
                details={
                    'risk_factors': risk_factors,
                    'indicators': custom_indicators,
                    'apk': apk_info,
                },
            )
            return matches
        except (yara.Error, OSError) as exc:
            logging.error('Error analyzing file %s: %s', file_path, exc)
            return []

    def quarantine_file(self, file_path):
        quarantine_dir = self.config.get('PATHS', 'quarantine_dir', fallback='quarantine')
        try:
            os.makedirs(quarantine_dir, exist_ok=True)
            destination = os.path.join(quarantine_dir, os.path.basename(file_path))
            if os.path.exists(destination):
                stem, extension = os.path.splitext(destination)
                destination = f'{stem}_{int(time.time())}_{uuid.uuid4().hex[:8]}{extension}'
            shutil.move(file_path, destination)
            logging.warning('QUARANTINED file %s to %s', file_path, destination)
            return destination
        except OSError as exc:
            logging.error('Failed to quarantine %s: %s', file_path, exc)
            return None

    def terminate_process(self, pid):
        try:
            psutil.Process(pid).terminate()
            logging.warning('TERMINATED process with PID: %s', pid)
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.Error) as exc:
            logging.error('Failed to terminate process %s: %s', pid, exc)
            return False

    def start_periodic_scans(self):
        interval = max(1, int(self.config.get('MONITORING', 'scan_interval', fallback=3600)))

        def scan_job():
            while self.monitoring_active and not self.stop_event.is_set():
                self.scan_critical_files()
                self.stop_event.wait(interval)

        logging.info('Periodic scanner started (interval=%ss)', interval)
        return self._start_background_thread(scan_job, 'PeriodicScan')

    def scan_critical_files(self):
        paths = [value.strip() for value in self.config.get(
            'PATHS', 'watch_paths', fallback='C:\\Windows\\System32;C:\\Windows\\SysWOW64'
        ).split(';') if value.strip()]
        quarantine_path = os.path.abspath(self.config.get(
            'PATHS', 'quarantine_dir', fallback='quarantine'
        )).lower()
        scanned = 0
        for root in paths:
            if not os.path.isdir(root):
                continue
            for current_root, directories, filenames in os.walk(root):
                directories[:] = [directory for directory in directories
                                  if os.path.commonpath([
                                      os.path.abspath(os.path.join(current_root, directory)).lower(),
                                      quarantine_path
                                  ]) != quarantine_path]
                for filename in filenames:
                    file_path = os.path.join(current_root, filename)
                    if self.should_scan_file(file_path):
                        scanned += 1
                        self.analyze_file(file_path, 'periodic scan')
        self.periodic_scan_count += 1
        self.last_periodic_scan = time.strftime('%Y-%m-%d %H:%M:%S')
        self.last_periodic_scan_files = scanned
        logging.info('Periodic scan completed: %d eligible files inspected', scanned)
        return scanned

    def get_status(self):
        paths = self.config.get('PATHS', 'watch_paths', fallback='C:\\Windows\\System32;C:\\Windows\\SysWOW64').split(';')
        threads = {thread.name: thread.is_alive() for thread in self.background_threads}
        return {
            'monitoring': self.monitoring_active,
            'paths': '\\n'.join(paths),
            'activities': self.suspicious_activities[-500:],
            'components': {
                'filesystem': bool(self.observer and self.observer.is_alive()),
                'processes': threads.get('ProcessMonitor', False),
                'periodic_scans': threads.get('PeriodicScan', False),
                'registry': threads.get('RegistryMonitor', False),
                'anomaly_detection': self.anomaly_detection and not self.learning_mode,
                'baseline_relationships': len(self.behavior_baseline['process_tree']),
                'scan_count': self.periodic_scan_count,
                'last_scan': self.last_periodic_scan,
                'last_scan_files': self.last_periodic_scan_files
            }
        }

# Flask API endpoints
hids = HIDS()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/status')
def status():
    return jsonify(hids.get_status())

@app.route('/api/start', methods=['POST'])
def start():
    success = hids.start_monitoring()
    return jsonify({'success': success, 'message': 'Monitoring started' if success else 'Monitoring already active'})

@app.route('/api/stop', methods=['POST'])
def stop():
    success = hids.stop_monitoring()
    return jsonify({'success': success, 'message': 'Monitoring stopped' if success else 'Monitoring already stopped'})

@app.route('/api/clear', methods=['POST'])
def clear():
    success = hids.clear_logs()
    return jsonify({'success': success, 'message': 'Logs cleared' if success else 'Failed to clear logs'})

if __name__ == "__main__":
    # If run with --learn, build anomaly baseline
    if '--learn' in sys.argv:
        hids.build_baseline()
        print("Baseline learning complete. Restart HIDS in normal mode.")
        sys.exit(0)
    app.run(host="127.0.0.1", port=5000, debug=False)
