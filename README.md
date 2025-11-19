# TheBigRat
It's a highly sophisticated Remote Access Trojan (RAT) designed for stealth, persistence, and comprehensive system control. Engineered with multiple layers of anti-analysis and anti-sandbox techniques, it can detect virtual machines, debuggers, and automated monitoring tools, ensuring it remains hidden from most security solutions.
Key capabilities include:

Immortality & Persistence: Self-respawning watchdog, registry entries, startup folder installation, and scheduled task creation to survive system restarts and termination attempts.

Advanced Privilege Escalation: Multiple stealthy UAC bypass methods to gain administrative control without triggering alerts.

Encrypted C2 Communication: Secure, multi-server command-and-control with XOR encryption and victim-specific identifiers for resilient remote management.

Data Exfiltration: Browser passwords, Discord tokens, cryptocurrency wallet manipulation, screenshots, webcam, microphone recordings, and keylogging.

Remote Command Execution: Executes arbitrary system commands sent from the C2 server, providing full remote access to the victim machine.

Stealth & Anti-Detection: Monitors mouse activity, system uptime, CPU timing, RAM, virtualization, and other indicators to avoid sandbox detection or automated analysis.
