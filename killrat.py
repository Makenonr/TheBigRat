# killrat.py
# Run this to COMPLETELY remove TheBigRat.py malware
# This will kill all processes, remove all persistence, and self-destruct

import os
import winreg
import subprocess
import shutil
import psutil
import sys
import time
import ctypes

class MalwareEradicator:
    def __init__(self):
        self.malware_patterns = [
            "STEALTH_IMMORTAL_2025", "ultimate_blackhat", "monster",
            "windowshelper", "syshelp", "maint", "systemhelper",
            "IMMORTAL_BLACKHAT", "stealth_cleaner", "rat.py"
        ]
        self.cleanup_log = []
        
    def log_action(self, action, status="SUCCESS"):
        """Log cleanup actions"""
        print(f"[{status}] {action}")
        self.cleanup_log.append(f"{action} - {status}")

    def kill_malware_processes(self):
        """Kill all running instances of the malware"""
        killed = []
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                proc_name = proc.info['name'].lower()
                proc_cmdline = ' '.join(proc.info['cmdline']).lower() if proc.info['cmdline'] else ""
                
                # Check if this is our malware
                is_malware = any(
                    pattern.lower() in proc_name or 
                    pattern.lower() in proc_cmdline 
                    for pattern in self.malware_patterns
                )
                
                # Also check for Python processes running suspicious scripts
                is_suspicious_python = (
                    "python" in proc_name and 
                    any(pattern.lower() in proc_cmdline for pattern in self.malware_patterns)
                )
                
                if is_malware or is_suspicious_python:
                    try:
                        # Try graceful termination first
                        proc.terminate()
                        proc.wait(timeout=3)
                        self.log_action(f"Terminated process: {proc.info['name']} (PID: {proc.info['pid']})")
                        killed.append(proc.info['pid'])
                    except (psutil.NoSuchProcess, psutil.TimeoutExpired):
                        try:
                            # Force kill if graceful fails
                            proc.kill()
                            self.log_action(f"Force killed process: {proc.info['name']}", "FORCE_KILL")
                            killed.append(proc.info['pid'])
                        except:
                            self.log_action(f"Failed to kill process: {proc.info['name']}", "FAILED")
                            
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
                
        return killed

    def remove_registry_persistence(self):
        """Remove all registry persistence entries"""
        removed = []
        
        registry_locations = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ]
        
        persistence_names = [
            "WindowsHelper", "SystemTools", "UserProfileService", "SysHelp",
            "Maint", "SystemHelper", "WindowsSecurityUpdate", "Maintenance",
            "UpdateService", "SecurityHealth", "WindowsDefender"
        ]
        
        for hive, key_path in registry_locations:
            try:
                key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_ALL_ACCESS)
                
                # Remove by known names
                for name in persistence_names:
                    try:
                        winreg.DeleteValue(key, name)
                        self.log_action(f"Removed registry: {key_path}\\{name}")
                        removed.append(f"{key_path}\\{name}")
                    except FileNotFoundError:
                        pass
                
                # Remove by pattern matching
                i = 0
                while True:
                    try:
                        value_name, value_data, _ = winreg.EnumValue(key, i)
                        if any(pattern.lower() in value_name.lower() or 
                              any(p.lower() in str(value_data).lower() for p in self.malware_patterns)
                              for pattern in self.malware_patterns):
                            try:
                                winreg.DeleteValue(key, value_name)
                                self.log_action(f"Removed registry by pattern: {key_path}\\{value_name}")
                                removed.append(f"{key_path}\\{value_name}")
                            except:
                                pass
                        i += 1
                    except OSError:
                        break
                        
                key.Close()
            except Exception as e:
                self.log_action(f"Failed to access registry: {key_path}", "ERROR")

        return removed

    def remove_startup_entries(self):
        """Remove malware from startup locations"""
        removed = []
        
        startup_paths = [
            os.path.join(os.environ["APPDATA"], r"Microsoft\Windows\Start Menu\Programs\Startup"),
            r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
            os.path.join(os.environ["USERPROFILE"], "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
        ]
        
        for startup_path in startup_paths:
            if os.path.exists(startup_path):
                for item in os.listdir(startup_path):
                    item_path = os.path.join(startup_path, item)
                    if any(pattern.lower() in item.lower() for pattern in self.malware_patterns):
                        try:
                            if os.path.isfile(item_path):
                                os.remove(item_path)
                                self.log_action(f"Removed startup file: {item}")
                                removed.append(item_path)
                            elif os.path.isdir(item_path):
                                shutil.rmtree(item_path, ignore_errors=True)
                                self.log_action(f"Removed startup folder: {item}")
                                removed.append(item_path)
                        except Exception as e:
                            self.log_action(f"Failed to remove startup: {item}", "ERROR")

        return removed

    def remove_scheduled_tasks(self):
        """Remove malicious scheduled tasks"""
        removed = []
        
        task_names = [
            "SysHelp", "Maint", "SystemHelper", "WindowsSecurityUpdate", 
            "Maintenance", "WindowsHelper", "UpdateService", "SecurityScan",
            "SystemTools", "UserProfileService"
        ]
        
        for task in task_names:
            try:
                # Check if task exists
                result = subprocess.run(
                    f'schtasks /query /tn "{task}"', 
                    shell=True, 
                    capture_output=True, 
                    text=True,
                    creationflags=0x8000000
                )
                
                if result.returncode == 0:  # Task exists
                    subprocess.run(
                        f'schtasks /delete /f /tn "{task}"', 
                        shell=True, 
                        capture_output=True,
                        creationflags=0x8000000
                    )
                    self.log_action(f"Removed scheduled task: {task}")
                    removed.append(task)
            except Exception as e:
                self.log_action(f"Failed to remove task: {task}", "ERROR")

        return removed

    def clean_filesystem(self):
        """Remove all malware files from system"""
        removed = []
        
        # Common locations to scan
        scan_locations = [
            os.getcwd(),
            os.environ['TEMP'],
            os.environ['APPDATA'],
            os.environ['USERPROFILE'],
            os.environ['PROGRAMDATA'],
            r"C:\\"
        ]
        
        for location in scan_locations:
            if not os.path.exists(location):
                continue
                
            try:
                for root, dirs, files in os.walk(location):
                    # Remove matching files
                    for file in files:
                        file_path = os.path.join(root, file)
                        if any(pattern.lower() in file.lower() for pattern in self.malware_patterns):
                            try:
                                os.remove(file_path)
                                self.log_action(f"Removed file: {file_path}")
                                removed.append(file_path)
                            except Exception as e:
                                # Try force delete
                                try:
                                    subprocess.run(f'del /f /q "{file_path}"', shell=True, capture_output=True)
                                    self.log_action(f"Force removed file: {file_path}")
                                except:
                                    self.log_action(f"Failed to remove file: {file}", "ERROR")
                    
                    # Remove matching directories
                    for dir in dirs:
                        dir_path = os.path.join(root, dir)
                        if any(pattern.lower() in dir.lower() for pattern in self.malware_patterns):
                            try:
                                shutil.rmtree(dir_path, ignore_errors=True)
                                self.log_action(f"Removed directory: {dir_path}")
                                removed.append(dir_path)
                            except:
                                self.log_action(f"Failed to remove directory: {dir}", "ERROR")
                                
            except Exception as e:
                self.log_action(f"Error scanning {location}", "ERROR")

        # Clean temporary artifacts
        temp_files = ["tmp.db", "tmp.wav", "Login Data", "Web Data", "Local State", "cleanup.bat"]
        for temp_file in temp_files:
            try:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
                    self.log_action(f"Removed temp file: {temp_file}")
            except:
                pass

        return removed

    def reset_windows_defender(self):
        """Re-enable Windows Defender if it was disabled"""
        try:
            # Re-enable Defender
            subprocess.run('powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $false"', 
                         shell=True, capture_output=True)
            subprocess.run('sc config WinDefend start= auto', shell=True, capture_output=True)
            subprocess.run('sc start WinDefend', shell=True, capture_output=True)
            
            # Re-enable firewall
            subprocess.run('netsh advfirewall set allprofiles state on', shell=True, capture_output=True)
            
            self.log_action("Re-enabled Windows Defender and Firewall")
        except:
            self.log_action("Failed to re-enable Windows Defender", "ERROR")

    def generate_report(self):
        """Generate cleanup report"""
        report = f"""
=== MALWARE ERADICATION REPORT ===
Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}

Cleanup Summary:
- Processes killed: {len([x for x in self.cleanup_log if 'Terminated' in x or 'killed' in x])}
- Registry entries removed: {len([x for x in self.cleanup_log if 'registry' in x.lower()])}
- Startup entries removed: {len([x for x in self.cleanup_log if 'startup' in x.lower()])}
- Scheduled tasks removed: {len([x for x in self.cleanup_log if 'task' in x.lower()])}
- Files removed: {len([x for x in self.cleanup_log if 'file' in x.lower() or 'directory' in x.lower()])}

Detailed Log:
{chr(10).join(f'  {log}' for log in self.cleanup_log)}

=== ERADICATION COMPLETE ===
        """
        print(report)

    def execute_cleanup(self):
        """Execute complete malware eradication"""
        print("=== STARTING MALWARE ERADICATION ===")
        print("This will permanently remove the STEALTH_IMMORTAL_2025 malware...")
        print("Press Ctrl+C within 5 seconds to cancel...")
        
        try:
            time.sleep(5)
        except KeyboardInterrupt:
            print("\n[!] Cleanup cancelled by user")
            return
        
        print("\n[!] Starting eradication process...")
        
        # Execute cleanup steps in sequence
        self.kill_malware_processes()
        time.sleep(2)  # Wait for processes to die
        
        self.remove_registry_persistence()
        self.remove_startup_entries() 
        self.remove_scheduled_tasks()
        self.clean_filesystem()
        self.reset_windows_defender()
        
        # Final cleanup pass
        time.sleep(3)
        self.kill_malware_processes()  # Kill any respawned processes
        
        print("\n[+] Malware eradication completed!")
        self.generate_report()
        
        # Self-destruct
        self.self_destruct()

    def self_destruct(self):
        """Remove this cleanup script itself"""
        print("\n[!] This cleanup script will now self-destruct...")
        time.sleep(3)
        
        try:
            if getattr(sys, 'frozen', False):
                # Compiled executable
                bat_content = f'''
@echo off
timeout /t 3 /nobreak >nul
del /f /q "{sys.executable}" >nul 2>&1
del /f /q "%~f0" >nul 2>&1
'''
            else:
                # Python script
                bat_content = f'''
@echo off
timeout /t 3 /nobreak >nul
del /f /q "{__file__}" >nul 2>&1
del /f /q "%~f0" >nul 2>&1
'''
            
            bat_path = os.path.join(os.environ['TEMP'], 'cleanup_final.bat')
            with open(bat_path, 'w') as f:
                f.write(bat_content)
            
            subprocess.Popen(f'"{bat_path}"', shell=True, creationflags=0x8000000)
            
        except:
            pass
        
        sys.exit(0)

# Main execution
if __name__ == "__main__":
    if os.name != 'nt':
        print("[-] This script only works on Windows systems")
        sys.exit(1)
    
    # Check if running as admin (recommended for complete cleanup)
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        if not is_admin:
            print("[!] Warning: Not running as administrator. Some cleanup may fail.")
            print("    For complete eradication, run as Administrator.")
            time.sleep(3)
    except:
        pass
    
    eradicator = MalwareEradicator()

    eradicator.execute_cleanup()

