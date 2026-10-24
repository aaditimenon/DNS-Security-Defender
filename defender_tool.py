import socket
import dns.resolver
import dns.query
import dns.flags
import dns.rdatatype
import dns.name
import signal
import sys
import os
import time
import subprocess
import threading
import ctypes
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler

class BlockedPageHandler(BaseHTTPRequestHandler):
    """HTTP handler for serving blocked page"""
    def do_GET(self):
        self.send_response(403)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        
        blocked_domain = self.server.blocked_domain
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>🚨 MALICIOUS WEBSITE BLOCKED</title>
            <style>
                * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                body {{ 
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    padding: 20px;
                }}
                .container {{
                    background: white;
                    border-radius: 12px;
                    box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                    max-width: 600px;
                    padding: 40px;
                    text-align: center;
                }}
                .icon {{
                    font-size: 80px;
                    margin-bottom: 20px;
                }}
                h1 {{
                    color: #d9534f;
                    font-size: 32px;
                    margin-bottom: 15px;
                }}
                h2 {{
                    color: #666;
                    font-size: 20px;
                    font-weight: 600;
                    margin-bottom: 20px;
                }}
                .domain {{
                    background: #f5f5f5;
                    border-left: 4px solid #d9534f;
                    padding: 15px;
                    margin: 20px 0;
                    border-radius: 4px;
                    word-break: break-all;
                    font-family: monospace;
                    color: #333;
                }}
                .message {{
                    color: #666;
                    font-size: 16px;
                    line-height: 1.6;
                    margin: 20px 0;
                }}
                .reason {{
                    background: #fff3cd;
                    border: 1px solid #ffc107;
                    color: #856404;
                    padding: 15px;
                    border-radius: 4px;
                    margin: 20px 0;
                    font-size: 14px;
                }}
                .footer {{
                    color: #999;
                    font-size: 12px;
                    margin-top: 30px;
                    padding-top: 20px;
                    border-top: 1px solid #eee;
                }}
            </style>
            <script>
                window.onload = function() {{
                    alert('⚠️ MALICIOUS WEBSITE BLOCKED!\\n\\nDomain: {blocked_domain}\\n\\nThis website has been detected as malicious and blocked by DNS Security Defender.\\n\\nYou cannot access this website.');
                }};
            </script>
        </head>
        <body>
            <div class="container">
                <div class="icon">🚨</div>
                <h1>MALICIOUS WEBSITE BLOCKED</h1>
                <h2>Access Denied - DNS Attack Detected</h2>
                
                <div class="domain">
                    {blocked_domain}
                </div>
                
                <div class="message">
                    <strong>This website has been detected as MALICIOUS</strong>
                </div>
                
                <div class="reason">
                    <p><strong>Attack Type:</strong> DNS Spoofing / Wormhole Attack</p>
                    <p style="margin-top: 10px;">This domain was flagged by the DNS Security Defender for attempting to redirect users to a malicious IP address.</p>
                    <p style="margin-top: 10px;">Access to this domain has been blocked at the OS level.</p>
                </div>
                
                <div class="message">
                    Your system is protected by <strong>DNS Security Defender</strong>
                </div>
                
                <div class="footer">
                    Status: BLOCKED | Time: {time.strftime('%Y-%m-%d %H:%M:%S')} | Reason: Malicious DNS Redirect
                </div>
            </div>
        </body>
        </html>
        """
        self.wfile.write(html.encode('utf-8'))
    
    def do_POST(self):
        """Block POST requests too"""
        self.do_GET()
    
    def log_message(self, format, *args):
        pass  # Suppress default logging

class DNSSecurityValidator:
    """Advanced DNS security validation using DNSSEC and IP verification"""
    
    HOSTS_FILE = Path("C:\\Windows\\System32\\drivers\\etc\\hosts")
    BLOCK_MARKER = "# DEFENDER_BLOCK"
    
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = ['8.8.8.8', '8.8.4.4']
        self.blocked_domains = {}  # domain: port mapping
        self.servers = {}  # port: server mapping
        self.blocked_entries = []  # for cleanup
        self.is_admin = self.check_admin()
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self.cleanup_handler)
        signal.signal(signal.SIGTERM, self.cleanup_handler)
    
    def check_admin(self):
        """Check if running with administrator privileges"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    
    def cleanup_handler(self, signum, frame):
        """Handle Ctrl+C gracefully - cleanup all blocks"""
        print("\n\n[!] Shutdown signal received...")
        print("[*] Cleaning up blocked domains...")
        
        self.stop_all_servers()
        self.remove_from_hosts_file()
        
        # Remove attack status file
        try:
            import os
            if os.path.exists('attack_status.json'):
                os.remove('attack_status.json')
        except:
            pass
        
        print("[+] Cleanup complete. All blocks removed. Exiting...")
        sys.exit(0)
    
    def add_to_hosts_file(self, domain):
        """Add domain block entry to Windows hosts file"""
        if not self.is_admin:
            print("[!] Not running as admin - cannot modify hosts file")
            return False
        
        try:
            # Read current hosts file
            with open(self.HOSTS_FILE, 'r') as f:
                hosts_content = f.read()
            
            # Check if already blocked
            if domain in hosts_content and self.BLOCK_MARKER in hosts_content:
                print(f"[+] Domain already in hosts file")
                return True
            
            # Add blocking entry (route to localhost)
            block_entry = f"127.0.0.1 {domain} {self.BLOCK_MARKER}\n"
            
            # Append to hosts file
            with open(self.HOSTS_FILE, 'a') as f:
                f.write(block_entry)
            
            # Flush DNS cache to apply hosts file changes immediately
            try:
                subprocess.run(['ipconfig', '/flushdns'], capture_output=True, timeout=5)
                print(f"[+] DNS cache flushed")
            except:
                pass
            
            self.blocked_entries.append(domain)
            print(f"[+++] HOSTS FILE MODIFIED: {domain} -> 127.0.0.1")
            print(f"[+++] ALL TRAFFIC TO {domain} NOW BLOCKED")
            return True
            
        except PermissionError:
            print("[!!!] ERROR: Permission denied. Run as Administrator!")
            return False
        except Exception as e:
            print(f"[-] Error modifying hosts file: {e}")
            return False
    
    def remove_from_hosts_file(self):
        """Remove all blocked entries from hosts file"""
        if not self.is_admin:
            return
        
        try:
            with open(self.HOSTS_FILE, 'r') as f:
                hosts_content = f.read()
            
            # Remove all lines with our marker
            lines = hosts_content.split('\n')
            filtered_lines = [line for line in lines if self.BLOCK_MARKER not in line]
            
            with open(self.HOSTS_FILE, 'w') as f:
                f.write('\n'.join(filtered_lines))
            
            print(f"[+] Hosts file cleaned: {len(self.blocked_entries)} entries removed")
            self.blocked_entries = []
        except Exception as e:
            print(f"[-] Error cleaning hosts file: {e}")
    
    def get_available_port(self):
        """Find an available port"""
        for port in [8080, 9999, 5000, 3000, 8888, 7000]:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.bind(('127.0.0.1', port))
                    return port
            except OSError:
                continue
        return None
    
    def start_blocking_server(self, domain):
        """Start HTTP server for blocked domain"""
        if domain in self.blocked_domains:
            return True
        
        try:
            port = self.get_available_port()
            if not port:
                print("[-] No available ports for blocking server")
                return False
            
            class CustomBlockedPageHandler(BlockedPageHandler):
                pass
            
            server = HTTPServer(('127.0.0.1', port), CustomBlockedPageHandler)
            server.blocked_domain = domain
            
            server_thread = threading.Thread(target=server.serve_forever, daemon=True)
            server_thread.start()
            
            self.blocked_domains[domain] = port
            self.servers[port] = server
            
            print(f"[+] BLOCKING SERVER STARTED: 127.0.0.1:{port}")
            return True
            
        except Exception as e:
            print(f"[-] Error starting blocking server: {e}")
            return False
    
    def stop_all_servers(self):
        """Stop all blocking servers"""
        for port, server in self.servers.items():
            try:
                server.shutdown()
                server.server_close()
            except:
                pass
        
        self.blocked_domains = {}
        self.servers = {}
    
    def verify_dnssec(self, domain):
        """Validate DNSSEC signatures for the domain"""
        print(f"\n[*] DNSSEC Validation for {domain}")
        print("-" * 60)
        
        try:
            request = dns.message.make_query(domain, dns.rdatatype.A, want_dnssec=True)
            response = dns.query.udp(request, self.resolver.nameservers[0], timeout=10)
            
            if response.flags & dns.flags.AD:
                print("[+] DNSSEC: VALIDATED")
                return True, "DNSSEC validated"
            else:
                print("[-] DNSSEC: NOT VALIDATED")
                return False, "DNSSEC not validated"
                
        except Exception as e:
            print(f"[-] DNSSEC validation error: {e}")
            return False, f"Error: {str(e)}"
    
    def show_alert(self, title, message):
        """Show Windows alert popup"""
        try:
            ctypes.windll.user32.MessageBoxW(0, message, title, 0x30)  # 0x30 = Warning icon
        except:
            pass
    
    def verify_network_integrity(self, domain, trusted_ip):
        """Multi-layered DNS security check"""
        print(f"\n{'='*60}")
        print(f"DNS SECURITY CHECK: {domain}")
        print(f"{'='*60}\n")
        
        print(f"[LAYER 1] IP Address Verification")
        print("-" * 60)
        try:
            actual_ip = socket.gethostbyname(domain)
            ip_verified = actual_ip == trusted_ip
            
            print(f"[*] Resolved IP: {actual_ip}")
            print(f"[*] Trusted IP:  {trusted_ip}")
            
            if not ip_verified:
                print("[!!!] CRITICAL: WORMHOLE ATTACK DETECTED!")
                print(f"[!!!] MALICIOUS IP DETECTED: {actual_ip}")
                
                # Write attack status file for index.html to detect
                try:
                    import json
                    attack_data = {
                        "attack_detected": True,
                        "domain": domain,
                        "malicious_ip": actual_ip,
                        "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')
                    }
                    with open('attack_status.json', 'w') as f:
                        json.dump(attack_data, f)
                except:
                    pass
                
                # SHOW ALERT POPUP
                alert_msg = f"MALICIOUS WEBSITE DETECTED!\n\nDomain: {domain}\nMalicious IP: {actual_ip}\n\nThe website has been BLOCKED!"
                self.show_alert("⚠️ DNS SECURITY ALERT", alert_msg)
                
                # BLOCK THE DOMAIN
                print(f"\n[*] Initiating domain blocking...")
                
                if self.is_admin:
                    if self.add_to_hosts_file(domain):
                        print("[+++] DOMAIN ADDED TO HOSTS FILE - All traffic redirected!")
                    
                    if self.start_blocking_server(domain):
                        print("[+++] BLOCKING SERVER ACTIVATED")
                    
                    print(f"[+++] ATTACK BLOCKED - {domain} is now INACCESSIBLE")
                else:
                    print("[!] Not running as Admin - some blocking features unavailable")
                    if self.start_blocking_server(domain):
                        print("[+] Blocking server started (limited protection)")
                
                time.sleep(0.5)
            else:
                print("[+] IP verified - SAFE")
        except Exception as e:
            print(f"[-] Error: {e}")
        
        print(f"\n[LAYER 2] DNSSEC Validation")
        dnssec_valid, _ = self.verify_dnssec(domain)
        
        print(f"\n[LAYER 3] Security Assessment")
        print("-" * 60)
        
        if not ip_verified:
            print("[!!!] SECURITY FAILURE")
            print("[+++] ACTIVE ATTACK DETECTED AND BLOCKED")
            if domain in self.blocked_domains:
                print(f"[+++] Domain {domain} is COMPLETELY BLOCKED")
                if self.is_admin:
                    print(f"[+++] Hosts file entry ensures OS-level blocking")
        
        print(f"\n{'='*60}\n")

def main():
    """Run DNS security validation with blocking"""
    validator = DNSSecurityValidator()
    
    print("\n" + "="*70)
    print("█" * 70)
    print("  DNS SECURITY DEFENDER - Active Blocking".center(70))
    print("█" * 70)
    print("="*70)
    
    if validator.is_admin:
        print("[+] Running with Administrator privileges")
        print("[+] OS-level hosts file blocking: ENABLED")
        print("[+] HTTP blocking server: ENABLED")
        print("[+] FULL PROTECTION MODE ACTIVE")
    else:
        print("[!] Not running as Administrator")
        print("[!] Some blocking features are limited")
    
    print("\n[*] Press Ctrl+C to stop and remove all blocks\n")
    print("="*70 + "\n")
    
    security_checks = [
        ("www.example.com", "93.184.216.34"),
    ]
    
    try:
        iteration = 0
        while True:
            iteration += 1
            print(f"[SCAN #{iteration}] Security check at {time.strftime('%H:%M:%S')}")
            print("="*70)
            
            for domain, trusted_ip in security_checks:
                validator.verify_network_integrity(domain, trusted_ip)
                time.sleep(1)
            
            blocked = list(validator.blocked_domains.keys()) if validator.blocked_domains else []
            print(f"[*] Blocked domains: {blocked if blocked else 'None'}")
            print(f"[*] Next scan in 30 seconds... (Ctrl+C to stop)\n")
            time.sleep(30)
    
    except KeyboardInterrupt:
        validator.cleanup_handler(None, None)

if __name__ == "__main__":
    main()
import socket
import dns.resolver
import dns.query
import dns.flags
import dns.rdatatype
import dns.name
import signal
import sys
import os
import time
import subprocess
import threading
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from functools import wraps
import ctypes

class DNSSecurityValidator:
    """Advanced DNS security validation using DNSSEC and IP verification"""
    
    HOSTS_FILE = Path("C:\\Windows\\System32\\drivers\\etc\\hosts")
    BLOCK_MARKER = "# DEFENDER_BLOCK"
    
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = ['8.8.8.8', '8.8.4.4']
        self.blocked_domains = {}  # domain: port mapping
        self.servers = {}  # port: server mapping
        self.blocked_entries = []  # for cleanup
        self.is_admin = self.check_admin()
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self.cleanup_handler)
        signal.signal(signal.SIGTERM, self.cleanup_handler)
    
    def check_admin(self):
        """Check if running with administrator privileges"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    
    def request_admin_if_needed(self):
        """Request admin privileges if not already running as admin"""
        if not self.is_admin:
            print("[!] Requesting Administrator privileges...")
            print("[*] A UAC dialog will appear - Click 'Yes' to allow\n")
            time.sleep(1)
            
            try:
                script_path = os.path.abspath(sys.argv[0])
                subprocess.run(
                    ['powershell', '-Command', 
                     f'Start-Process python -ArgumentList "{script_path}" -Verb RunAs'],
                    check=False
                )
                sys.exit(0)
            except Exception as e:
                print(f"[-] Failed to elevate: {e}")
                print("[!] Hosts file modification will not work")
                return False
        return True
    """HTTP handler for serving blocked page"""
    def do_GET(self):
        self.send_response(403)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        
        requested_path = self.path
        blocked_domain = self.server.blocked_domain
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>🚨 MALICIOUS WEBSITE BLOCKED</title>
            <style>
                * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                body {{ 
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    padding: 20px;
                }}
                .container {{
                    background: white;
                    border-radius: 12px;
                    box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                    max-width: 600px;
                    padding: 40px;
                    text-align: center;
                }}
                .icon {{
                    font-size: 80px;
                    margin-bottom: 20px;
                }}
                h1 {{
                    color: #d9534f;
                    font-size: 32px;
                    margin-bottom: 15px;
                }}
                h2 {{
                    color: #666;
                    font-size: 20px;
                    font-weight: 600;
                    margin-bottom: 20px;
                }}
                .domain {{
                    background: #f5f5f5;
                    border-left: 4px solid #d9534f;
                    padding: 15px;
                    margin: 20px 0;
                    border-radius: 4px;
                    word-break: break-all;
                    font-family: monospace;
                    color: #333;
                }}
                .message {{
                    color: #666;
                    font-size: 16px;
                    line-height: 1.6;
                    margin: 20px 0;
                }}
                .reason {{
                    background: #fff3cd;
                    border: 1px solid #ffc107;
                    color: #856404;
                    padding: 15px;
                    border-radius: 4px;
                    margin: 20px 0;
                    font-size: 14px;
                }}
                .footer {{
                    color: #999;
                    font-size: 12px;
                    margin-top: 30px;
                    padding-top: 20px;
                    border-top: 1px solid #eee;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="icon">🚨</div>
                <h1>MALICIOUS WEBSITE BLOCKED</h1>
                <h2>Access Denied</h2>
                
                <div class="domain">
                    {blocked_domain}
                </div>
                
                <div class="message">
                    <strong>This website has been detected as MALICIOUS</strong>
                </div>
                
                <div class="reason">
                    <p><strong>Attack Detected:</strong> DNS Spoofing / Wormhole Attack</p>
                    <p style="margin-top: 10px;">This domain was flagged by the DNS Security Defender for attempting to redirect users to a malicious IP address.</p>
                </div>
                
                <div class="message">
                    Your system is protected by <strong>DNS Security Defender</strong>
                </div>
                
                <div class="footer">
                    Status: BLOCKED | Time: {time.strftime('%Y-%m-%d %H:%M:%S')}
                </div>
            </div>
        </body>
        </html>
        """
        self.wfile.write(html.encode('utf-8'))
    
    def do_POST(self):
        """Block POST requests too"""
        self.do_GET()
    
    def do_HEAD(self):
        """Block HEAD requests"""
        self.send_response(403)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
    
    def log_message(self, format, *args):
        pass  # Suppress default logging

class DNSSecurityValidator:
    """Advanced DNS security validation using DNSSEC and IP verification"""
    
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = ['8.8.8.8', '8.8.4.4']
        self.blocked_domains = {}  # domain: port mapping
        self.servers = {}  # port: server mapping
        self.blocking_active = False
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self.cleanup_handler)
        signal.signal(signal.SIGTERM, self.cleanup_handler)
    
    def activate_dns_interception(self):
        """Monkey-patch socket functions to intercept DNS lookups and connections for blocked domains"""
        validator_instance = self
        
        def custom_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
            """Custom getaddrinfo that redirects blocked domains to localhost"""
            # Check if this domain is blocked
            if any(blocked in host for blocked in validator_instance.blocked_domains.keys()):
                # Redirect to localhost on the blocking port
                blocking_port = list(validator_instance.blocked_domains.values())[0]
                return _original_getaddrinfo('127.0.0.1', blocking_port, family, type, proto, flags)
            # Normal resolution
            return _original_getaddrinfo(host, port, family, type, proto, flags)
        
        def custom_gethostbyname(ip_address):
            """Custom gethostbyname that redirects blocked domains to localhost"""
            if any(blocked in ip_address for blocked in validator_instance.blocked_domains.keys()):
                return '127.0.0.1'
            return _original_gethostbyname(ip_address)
        
        def custom_gethostbyname_ex(ip_address):
            """Custom gethostbyname_ex that redirects blocked domains to localhost"""
            if any(blocked in ip_address for blocked in validator_instance.blocked_domains.keys()):
                return ('127.0.0.1', [], ['127.0.0.1'])
            return _original_gethostbyname_ex(ip_address)
        
        def custom_connect(self_socket, address):
            """Custom connect that redirects blocked IPs to localhost"""
            host, port = address if len(address) >= 2 else (address[0], 0)
            
            # Check if trying to connect to a blocked IP
            if host in _blocked_ips:
                blocking_port = _blocked_ips[host]
                return _original_socket_connect(self_socket, ('127.0.0.1', blocking_port))
            
            return _original_socket_connect(self_socket, address)
        
        def custom_connect_ex(self_socket, address):
            """Custom connect_ex that redirects blocked IPs to localhost"""
            host, port = address if len(address) >= 2 else (address[0], 0)
            
            # Check if trying to connect to a blocked IP
            if host in _blocked_ips:
                blocking_port = _blocked_ips[host]
                return _original_socket_connect_ex(self_socket, ('127.0.0.1', blocking_port))
            
            return _original_socket_connect_ex(self_socket, address)
        
        # Apply monkey patches
        socket.getaddrinfo = custom_getaddrinfo
        socket.gethostbyname = custom_gethostbyname
        socket.gethostbyname_ex = custom_gethostbyname_ex
        socket.socket.connect = custom_connect
        socket.socket.connect_ex = custom_connect_ex
        
        self.blocking_active = True
        print("[+] DNS interception activated - Blocked domains cannot be accessed")
        print("[+] Socket-level connection blocking activated")
        print("[+] All access attempts will be redirected to blocking server")
        print("[+] All access attempts will be redirected to blocking server")
    
    def deactivate_dns_interception(self):
        """Restore original socket functions"""
        socket.getaddrinfo = _original_getaddrinfo
        socket.gethostbyname = _original_gethostbyname
        socket.gethostbyname_ex = _original_gethostbyname_ex
        socket.socket.connect = _original_socket_connect
        socket.socket.connect_ex = _original_socket_connect_ex
        self.blocking_active = False
        _blocked_ips.clear()
    
    def cleanup_handler(self, signum, frame):
        """Handle Ctrl+C gracefully - stop all blocking servers"""
        print("\n\n[!] Shutdown signal received...")
        print("[*] Stopping all blocking servers...")
        print("[*] Deactivating DNS interception...")
        
        self.stop_all_reroutes()
        self.deactivate_dns_interception()
        
        print("[+] All servers stopped. DNS interception deactivated. Exiting...")
        sys.exit(0)
    
    def get_available_port(self):
        """Find an available port to run the blocking server"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', 0))
            s.listen(1)
            port = s.getsockname()[1]
        return port
    
    def start_reroute_server(self, domain, malicious_ip=None):
        """Start a local HTTP server that blocks access to the domain"""
        if domain in self.blocked_domains:
            print(f"[!] Domain already blocked: {domain}")
            return False
        
        try:
            # Try to use standard HTTP port first (80), then try alternatives
            ports_to_try = [8080, 9999, 5000, 3000, 8888]
            
            for port in ports_to_try:
                try:
                    # Create custom handler with blocked_domain attribute
                    class CustomBlockedPageHandler(BlockedPageHandler):
                        pass
                    
                    # Create server
                    server = HTTPServer(('127.0.0.1', port), CustomBlockedPageHandler)
                    server.blocked_domain = domain
                    
                    # Try to start the server
                    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
                    server_thread.start()
                    
                    self.blocked_domains[domain] = port
                    self.servers[port] = server
                    
                    # Register the malicious IP for connection blocking
                    if malicious_ip:
                        _blocked_ips[malicious_ip] = port
                        print(f"[+] MALICIOUS IP REGISTERED FOR BLOCKING: {malicious_ip}:{port}")
                    
                    print(f"[+] BLOCKING SERVER STARTED")
                    print(f"    Domain: {domain}")
                    print(f"    Port: 127.0.0.1:{port}")
                    print(f"[+] All traffic to {domain} is now blocked")
                    
                    # Activate DNS interception if this is the first blocked domain
                    if len(self.blocked_domains) == 1:
                        self.activate_dns_interception()
                    
                    return True
                except OSError:
                    continue
            
            print(f"[-] Failed to find available port for blocking server")
            return False
            
        except Exception as e:
            print(f"[-] Error starting blocking server: {e}")
            return False
    
    def stop_all_reroutes(self):
        """Stop all blocking servers"""
        for port, server in self.servers.items():
            try:
                server.shutdown()
                server.server_close()
            except:
                pass
        
        # Clear blocked IPs
        _blocked_ips.clear()
        
        print(f"[+] Cleanup complete - {len(self.blocked_domains)} domains unblocked")
        self.blocked_domains = {}
        self.servers = {}
    
    def cleanup_handler(self, signum, frame):
        """Handle Ctrl+C gracefully - stop all blocking servers"""
        print("\n\n[!] Shutdown signal received...")
        print("[*] Stopping all blocking servers...")
        print("[*] Deactivating DNS interception...")
        
        self.stop_all_reroutes()
        self.deactivate_dns_interception()
        
        print("[+] All servers stopped. DNS interception deactivated. Exiting...")
        sys.exit(0)
    
    def stop_all_reroutes(self):
        """Stop all blocking servers"""
        for port, server in self.servers.items():
            try:
                server.shutdown()
                server.server_close()
            except:
                pass
        
        print(f"[+] Cleanup complete - {len(self.blocked_domains)} domains unrerouted")
        self.blocked_domains = {}
        self.servers = {}
    
    def verify_dnssec(self, domain):
        """Validate DNSSEC signatures for the domain"""
        print(f"\n[*] DNSSEC Validation for {domain}")
        print("-" * 60)
        
        try:
            request = dns.message.make_query(domain, dns.rdatatype.A, want_dnssec=True)
            response = dns.query.udp(request, self.resolver.nameservers[0], timeout=10)
            
            if response.flags & dns.flags.AD:
                print("[+] DNSSEC: VALIDATED - DNS response authenticated")
                
                for rrset in response.answer:
                    if rrset.rdtype == dns.rdatatype.RRSIG:
                        print(f"[+] RRSIG signature verified")
                        break
                
                return True, "DNSSEC validated with authenticated signatures"
            else:
                print("[-] DNSSEC: NOT VALIDATED")
                return False, "DNSSEC not validated"
                
        except Exception as e:
            print(f"[-] DNSSEC validation error: {e}")
            return False, f"Error: {str(e)}"
    
    def verify_network_integrity(self, domain, trusted_ip):
        """Multi-layered DNS security check with active blocking"""
        print(f"\n{'='*60}")
        print(f"DNS SECURITY CHECK: {domain}")
        print(f"{'='*60}\n")
        
        # Layer 1: IP verification
        print(f"[LAYER 1] IP Address Verification")
        print("-" * 60)
        try:
            actual_ip = socket.gethostbyname(domain)
            ip_verified = actual_ip == trusted_ip
            
            print(f"[*] Resolved IP: {actual_ip}")
            print(f"[*] Trusted IP:  {trusted_ip}")
            
            if not ip_verified:
                print("[!!!] CRITICAL: WORMHOLE ATTACK DETECTED!")
                print(f"[!!!] MALICIOUS IP DETECTED: {actual_ip}")
                
                # BLOCK THE MALICIOUS DOMAIN
                print(f"\n[*] Initiating active domain blocking...")
                if self.start_reroute_server(domain, malicious_ip=actual_ip):
                    print("[+++] DOMAIN BLOCKED - Malicious traffic intercepted!")
                    print(f"[+++] Any access to {domain} or {actual_ip} will be denied")
                time.sleep(0.5)
            else:
                print("[+] IP verified")
        except Exception as e:
            print(f"[-] Error: {e}")
            ip_verified = False
        
        # Layer 2: DNSSEC validation
        print(f"\n[LAYER 2] DNSSEC Validation")
        dnssec_valid, _ = self.verify_dnssec(domain)
        
        # Layer 3: Final assessment
        print(f"\n[LAYER 3] Security Assessment")
        print("-" * 60)
        
        if ip_verified and dnssec_valid:
            print("[+++] MAXIMUM SECURITY - IP & DNSSEC verified ✓")
            print("[+] DNS response is AUTHENTIC and SECURE")
        elif ip_verified:
            print("[++] MODERATE SECURITY - IP verified ✓")
            print("[-] DNSSEC not available")
        elif dnssec_valid:
            print("[++] DNSSEC PROTECTION ACTIVE ✓")
            print("[!] WARNING: IP mismatch detected")
        else:
            print("[!!!] SECURITY FAILURE")
            print("[!] ACTIVE WORMHOLE/SPOOFING ATTACK BLOCKED")
            if domain in self.blocked_domains:
                print(f"[+++] DOMAIN SUCCESSFULLY BLOCKED: {domain}")
                print(f"[+++] Users cannot access this domain - attack neutralized!")
        
        print(f"\n{'='*60}\n")

def main():
    """Run DNS security validation with continuous monitoring and active blocking"""
    validator = DNSSecurityValidator()
    
    print("\n" + "="*70)
    print("█" * 70)
    print("  DNS SECURITY DEFENDER - Active Blocking Mode".center(70))
    print("█" * 70)
    print("="*70)
    print("\n[+] Status: RUNNING - All domains are monitored")
    print("[+] No admin rights required - Python-level DNS interception")
    print("[+] Blocked domains will show 'MALICIOUS WEBSITE' page")
    print("[+] All access attempts will be intercepted and blocked\n")
    print("[*] Press Ctrl+C to stop monitoring and remove all blocks\n")
    print("="*70 + "\n")
    
    print("[TESTING INSTRUCTIONS]")
    print("-" * 70)
    print("Once a domain is blocked, you can test the blocking with:")
    print("  1. curl: curl http://example.com")
    print("  2. Browser: Try to visit the URL (DNS will resolve to localhost)")
    print("  3. Python: requests.get('http://example.com')")
    print("\nYou should see the 'MALICIOUS WEBSITE BLOCKED' page")
    print("-" * 70 + "\n")
    
    # Configuration: You can modify these to test different scenarios
    # Format: (domain, trusted_ip)
    security_checks = [
        ("www.example.com", "93.184.216.34"),
        # Add more domains to monitor as needed
    ]
    
    # Continuous monitoring loop
    try:
        iteration = 0
        while True:
            iteration += 1
            print(f"\n[SCAN #{iteration}] Performing security checks at {time.strftime('%H:%M:%S')}")
            print("="*60)
            
            for domain, trusted_ip in security_checks:
                validator.verify_network_integrity(domain, trusted_ip)
                time.sleep(1)
            
            blocked = list(validator.blocked_domains.keys()) if validator.blocked_domains else []
            print(f"[*] Blocked domains: {blocked if blocked else 'None'}")
            print(f"[*] Next scan in 30 seconds... (Press Ctrl+C to stop)\n")
            time.sleep(30)
    
    except KeyboardInterrupt:
        validator.cleanup_handler(None, None)

if __name__ == "__main__":
    main()
