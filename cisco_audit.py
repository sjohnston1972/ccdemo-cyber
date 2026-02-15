#!/usr/bin/env python3
"""
Cisco Switch Security Audit Script
Performs non-intrusive security assessment of Cisco network devices
"""

import os
import sys
import time
from dotenv import load_dotenv
import paramiko
import socket
from datetime import datetime

# Load environment variables
load_dotenv()

DEVICE_IP = os.getenv("DEVICE_IP")
SSH_USERNAME = os.getenv("SSH_USERNAME")
SSH_PASSWORD = os.getenv("SSH_PASSWORD")

class CiscoSecurityAuditor:
    def __init__(self, host, username, password):
        self.host = host
        self.username = username
        self.password = password
        self.findings = []
        self.client = None

    def add_finding(self, risk_level, title, description, evidence, remediation):
        """Add a security finding to the report"""
        self.findings.append({
            'risk_level': risk_level,
            'title': title,
            'description': description,
            'evidence': evidence,
            'remediation': remediation
        })

    def test_connectivity(self):
        """Test basic connectivity to the device"""
        print(f"\n[*] Testing connectivity to {self.host}...")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((self.host, 22))
            sock.close()

            if result == 0:
                print(f"[+] SSH port (22) is open")
                return True
            else:
                print(f"[-] SSH port (22) is closed or filtered")
                return False
        except socket.error as e:
            print(f"[-] Connection error: {e}")
            return False

    def check_open_ports(self):
        """Check for common management ports"""
        print(f"\n[*] Checking common management ports...")

        common_ports = {
            22: 'SSH',
            23: 'Telnet',
            80: 'HTTP',
            443: 'HTTPS',
            161: 'SNMP',
            162: 'SNMP Trap',
            514: 'Syslog',
        }

        open_ports = []

        for port, service in common_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((self.host, port))
                sock.close()

                if result == 0:
                    print(f"[+] Port {port} ({service}) - OPEN")
                    open_ports.append((port, service))

                    # Generate findings for risky services
                    if port == 23:
                        self.add_finding(
                            'HIGH',
                            'Telnet Service Enabled',
                            'Telnet transmits credentials and data in clear text, exposing them to interception.',
                            f'Port 23 (Telnet) is open on {self.host}',
                            'Disable Telnet and use SSH exclusively: "no transport input telnet" or "transport input ssh"'
                        )
                    elif port == 80:
                        self.add_finding(
                            'MEDIUM',
                            'HTTP Management Interface Exposed',
                            'HTTP does not encrypt management traffic, making credentials and configuration vulnerable.',
                            f'Port 80 (HTTP) is open on {self.host}',
                            'Disable HTTP and use HTTPS only: "no ip http server" and "ip http secure-server"'
                        )
                    elif port == 161:
                        self.add_finding(
                            'MEDIUM',
                            'SNMP Service Detected',
                            'SNMP, especially SNMPv1/v2c with default community strings, can expose device information.',
                            f'Port 161 (SNMP) is open on {self.host}',
                            'Audit SNMP configuration: Use SNMPv3 with authentication, disable if not needed, change default community strings'
                        )

            except socket.error:
                pass

        return open_ports

    def connect_ssh(self):
        """Establish SSH connection"""
        print(f"\n[*] Establishing SSH connection...")
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(
                self.host,
                username=self.username,
                password=self.password,
                timeout=10,
                look_for_keys=False,
                allow_agent=False
            )

            # Start interactive shell for Cisco devices
            self.shell = self.client.invoke_shell()
            self.shell.settimeout(10)

            # Wait for initial prompt and disable paging
            time.sleep(2)
            self.shell.recv(65535)  # Clear initial output

            # Disable paging
            self.shell.send('terminal length 0\n')
            time.sleep(1)
            self.shell.recv(65535)  # Clear command output

            print("[+] SSH connection established")
            return True
        except paramiko.AuthenticationException:
            print("[-] Authentication failed")
            self.add_finding(
                'INFORMATIONAL',
                'SSH Authentication Test',
                'SSH authentication with provided credentials failed.',
                'Authentication unsuccessful',
                'Verify credentials or check AAA configuration'
            )
            return False
        except Exception as e:
            print(f"[-] SSH connection failed: {e}")
            return False

    def execute_command(self, command):
        """Execute a command on the Cisco device"""
        try:
            # Send command
            self.shell.send(command + '\n')
            time.sleep(2)  # Wait for command execution

            # Receive output
            output = ''
            while self.shell.recv_ready():
                chunk = self.shell.recv(65535).decode('utf-8', errors='ignore')
                output += chunk
                time.sleep(0.5)

            # Remove command echo and prompt
            lines = output.split('\n')
            if len(lines) > 1:
                output = '\n'.join(lines[1:-1])  # Remove first (command) and last (prompt) lines

            return output
        except Exception as e:
            print(f"[-] Error executing command '{command}': {e}")
            return None

    def audit_device_info(self):
        """Gather basic device information"""
        print(f"\n[*] Gathering device information...")

        commands = [
            'show version',
            'show inventory',
        ]

        device_info = {}
        for cmd in commands:
            output = self.execute_command(cmd)
            if output:
                device_info[cmd] = output
                print(f"[+] Executed: {cmd}")

        return device_info

    def audit_running_config_security(self):
        """Audit security-relevant configuration items"""
        print(f"\n[*] Auditing security configuration...")

        security_commands = [
            'show running-config | include username',
            'show running-config | include enable',
            'show running-config | include line vty',
            'show running-config | include line con',
            'show running-config | include snmp',
            'show running-config | include ip http',
            'show running-config | include aaa',
            'show running-config | include service password-encryption',
            'show running-config | include logging',
            'show running-config | include ntp',
            'show cdp neighbors',
            'show vtp status',
            'show ip interface brief',
        ]

        config_data = {}
        for cmd in security_commands:
            output = self.execute_command(cmd)
            if output:
                config_data[cmd] = output
                print(f"[+] Executed: {cmd}")

                # Analyze output for security issues
                self.analyze_config_output(cmd, output)

        return config_data

    def analyze_config_output(self, command, output):
        """Analyze command output for security issues"""

        # Check for unencrypted passwords
        if 'enable' in command and 'password' in output.lower():
            if 'enable password' in output.lower() and 'enable secret' not in output.lower():
                self.add_finding(
                    'HIGH',
                    'Unencrypted Enable Password',
                    'Enable password is configured without encryption (MD5 hash).',
                    output.strip(),
                    'Use "enable secret" instead of "enable password" for stronger encryption'
                )

        # Check for password encryption service
        if 'service password-encryption' in command:
            if 'service password-encryption' not in output:
                self.add_finding(
                    'MEDIUM',
                    'Password Encryption Not Enabled',
                    'Service password-encryption is not configured, leaving passwords visible in config.',
                    'Command not found in configuration',
                    'Enable password encryption: "service password-encryption"'
                )

        # Check for HTTP server
        if 'ip http' in command:
            if 'ip http server' in output and 'no ip http server' not in output:
                # Already captured in port scan, but add config evidence
                pass

        # Check VTY configuration
        if 'line vty' in command:
            if 'transport input all' in output:
                self.add_finding(
                    'HIGH',
                    'VTY Allows All Transport Protocols',
                    'VTY lines accept all transport protocols including insecure Telnet.',
                    output.strip(),
                    'Restrict VTY to SSH only: "transport input ssh"'
                )

        # Check CDP neighbors
        if 'cdp neighbors' in command and output.strip() and 'not enabled' not in output.lower():
            if len(output.strip().split('\n')) > 2:
                self.add_finding(
                    'LOW',
                    'CDP Enabled and Broadcasting',
                    'Cisco Discovery Protocol (CDP) broadcasts device information that could aid reconnaissance.',
                    f'CDP neighbors detected:\n{output.strip()}',
                    'Consider disabling CDP on external-facing interfaces: "no cdp enable" (interface level) or globally if not needed'
                )

        # Check AAA
        if 'aaa' in command:
            if not output or len(output.strip()) < 5:
                self.add_finding(
                    'MEDIUM',
                    'AAA Not Configured',
                    'Authentication, Authorization, and Accounting (AAA) is not configured.',
                    'No AAA configuration found',
                    'Implement AAA for centralized authentication and logging: "aaa new-model"'
                )

        # Check NTP
        if 'ntp' in command:
            if not output or 'ntp server' not in output.lower():
                self.add_finding(
                    'LOW',
                    'NTP Not Configured',
                    'Network Time Protocol is not configured, which may affect logging accuracy and certificate validation.',
                    'No NTP server configured',
                    'Configure NTP: "ntp server <ip-address>"'
                )

        # Check logging
        if 'logging' in command:
            if not output or 'logging' not in output.lower():
                self.add_finding(
                    'MEDIUM',
                    'Remote Logging Not Configured',
                    'No remote logging server configured, limiting audit trail and incident response capabilities.',
                    'No logging configuration found',
                    'Configure remote logging: "logging host <syslog-server>"'
                )

    def generate_report(self):
        """Generate comprehensive security audit report"""
        print("\n" + "="*80)
        print("CISCO SWITCH SECURITY AUDIT REPORT")
        print("="*80)
        print(f"Target Device: {self.host}")
        print(f"Audit Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total Findings: {len(self.findings)}")
        print("="*80)

        # Group findings by risk level
        risk_levels = ['HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']

        for risk_level in risk_levels:
            level_findings = [f for f in self.findings if f['risk_level'] == risk_level]

            if level_findings:
                print(f"\n{'='*80}")
                print(f"{risk_level} RISK FINDINGS ({len(level_findings)})")
                print(f"{'='*80}")

                for i, finding in enumerate(level_findings, 1):
                    print(f"\n[{risk_level}] Finding #{i}: {finding['title']}")
                    print(f"\nDescription:")
                    print(f"  {finding['description']}")
                    print(f"\nEvidence:")
                    for line in finding['evidence'].split('\n'):
                        print(f"  {line}")
                    print(f"\nRemediation:")
                    print(f"  {finding['remediation']}")
                    print("-" * 80)

        print("\n" + "="*80)
        print("END OF REPORT")
        print("="*80)

    def run_audit(self):
        """Main audit workflow"""
        print("\n" + "="*80)
        print("CISCO SWITCH SECURITY AUDIT")
        print("="*80)
        print(f"Target: {self.host}")
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*80)

        # Phase 1: Network reconnaissance
        if not self.test_connectivity():
            print("\n[!] Cannot reach target device. Aborting audit.")
            return False

        self.check_open_ports()

        # Phase 2: SSH-based configuration audit
        if self.connect_ssh():
            self.audit_device_info()
            self.audit_running_config_security()
            self.client.close()
        else:
            print("\n[!] Could not establish SSH connection for detailed audit.")

        # Phase 3: Generate report
        self.generate_report()

        return True

def main():
    # Validate environment variables
    if not all([DEVICE_IP, SSH_USERNAME, SSH_PASSWORD]):
        print("[!] Error: Missing required environment variables in .env file")
        print("    Required: DEVICE_IP, SSH_USERNAME, SSH_PASSWORD")
        sys.exit(1)

    # Run audit
    auditor = CiscoSecurityAuditor(DEVICE_IP, SSH_USERNAME, SSH_PASSWORD)
    auditor.run_audit()

if __name__ == "__main__":
    main()
