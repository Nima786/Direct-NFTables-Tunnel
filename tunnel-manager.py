#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import subprocess
import shutil
import re
import time
import argparse
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

# --- Configuration & Version ---
VERSION = '2.1.0'

# --- Constants for Direct Tunnels ---
DIRECT_TUNNELS_DB_FILE = '/etc/tunnel_manager/direct_tunnels.json'
DIRECT_TUNNEL_RULES_FILE = '/etc/nftables.d/direct-tunnels.nft'

# --- Constants for Reverse Tunnels ---
REVERSE_DB_DIR = '/etc/reverse_tunnel_manager'
REVERSE_PEERS_DB_FILE = os.path.join(REVERSE_DB_DIR, 'peers.json')
REVERSE_TUNNELS_DB_FILE = os.path.join(REVERSE_DB_DIR, 'tunnels.json')
REVERSE_TUNNEL_RULES_FILE = '/etc/nftables.d/reverse-tunnels.nft'
WG_CONFIG_FILE = '/etc/wireguard/wg0.conf'
CALLBACK_PORT = 58080
SCRIPT_URL = "https://raw.githubusercontent.com/Nima786/Direct-NFTables-Tunnel/main/ultimate-tunnel-manager.py"

# --- General Constants ---
MAIN_NFT_CONFIG = '/etc/nftables.conf'


# --- Color Codes ---
class C:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'


# --- Helper Functions (Shared) ---
def clear_screen():
    os.system('clear')


def press_enter_to_continue():
    input(f"\n{C.YELLOW}Press Enter to return to the menu...{C.END}")


def run_command(command, use_sudo=True, capture=True, text=True, shell=False, command_input=None):
    if use_sudo and os.geteuid() != 0:
        if not shell:
            command = ['sudo'] + command
        else:
            command = 'sudo ' + command
    try:
        return subprocess.run(
            command, check=True, capture_output=capture, text=text,
            shell=shell, input=command_input
        )
    except subprocess.CalledProcessError:
        return None


def is_valid_ip(ip_str):
    """Checks if a string is a valid IPv4 address."""
    pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    if not pattern.match(ip_str):
        return False
    parts = ip_str.split('.')
    for item in parts:
        if not 0 <= int(item) <= 255:
            return False
    return True


def parse_ports_to_set(ports_str):
    """Parses a string of ports (e.g., "80,443,1000-2000") into a set of integers."""
    ports = set()
    if not ports_str:
        return ports
    try:
        parts = ports_str.split(',')
        for part in parts:
            part = part.strip()
            if not part:
                continue
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.update(range(start, end + 1))
            else:
                ports.add(int(part))
        return ports
    except ValueError:
        return None


def ensure_dependencies(packages):
    """Checks for and installs missing dependencies."""
    needs_install = [pkg for pkg, cmd in packages.items() if not shutil.which(cmd)]
    if needs_install:
        print(f"{C.YELLOW}Missing dependencies: {', '.join(needs_install)}. Attempting to install...{C.END}")
        run_command(['apt-get', 'update', '-y'], capture=False)
        for pkg in needs_install:
            if not run_command(['apt-get', 'install', pkg, '-y'], capture=False):
                print(f"{C.RED}Failed to install {pkg}. Please install it manually.{C.END}")
                return False
    return True


def ensure_ip_forwarding():
    result = run_command(['sysctl', 'net.ipv4.ip_forward'])
    if result and result.stdout.strip() == 'net.ipv4.ip_forward = 1':
        return
    print(f"{C.YELLOW}Enabling IP forwarding...{C.END}")
    run_command(['sysctl', '-w', 'net.ipv4.ip_forward=1'])
    try:
        with open('/etc/sysctl.conf', 'r+') as f:
            content = f.read()
            if 'net.ipv4.ip_forward=1' not in content:
                f.write('\nnet.ipv4.ip_forward=1\n')
            elif '#net.ipv4.ip_forward=1' in content:
                content = content.replace('#net.ipv4.ip_forward=1', 'net.ipv4.ip_forward=1')
                f.seek(0)
                f.write(content)
                f.truncate()
        run_command(['sysctl', '-p'])
    except Exception as e:
        print(f"{C.RED}Error updating /etc/sysctl.conf: {e}{C.END}")


def ensure_nftables_service():
    is_enabled_result = run_command(['systemctl', 'is-enabled', 'nftables'])
    if is_enabled_result and is_enabled_result.stdout.strip() != 'enabled':
        run_command(['systemctl', 'enable', 'nftables'])

    is_active_result = run_command(['systemctl', 'is-active', 'nftables'])
    if is_active_result and is_active_result.stdout.strip() not in ['active', 'activating']:
        run_command(['systemctl', 'start', 'nftables'])


def ensure_include_line():
    """Ensures the main nftables config includes rules from /etc/nftables.d/"""
    include_line = 'include "/etc/nftables.d/*.nft"'
    if not os.path.exists(MAIN_NFT_CONFIG):
        print(f"{C.YELLOW}{MAIN_NFT_CONFIG} not found. Creating default...{C.END}")
        with open(MAIN_NFT_CONFIG, 'w') as f:
            f.write(f"#!/usr/sbin/nft -f\nflush ruleset\n\n{include_line}\n")
        return True
    with open(MAIN_NFT_CONFIG, 'r') as f:
        if include_line in f.read():
            return True
    print(f"{C.YELLOW}Adding include line to {MAIN_NFT_CONFIG}...{C.END}")
    with open(MAIN_NFT_CONFIG, 'a') as f:
        f.write(f"\n# Added by Ultimate Tunnel Manager\n{include_line}\n")
    return True

################################################################################
# --- DIRECT TUNNEL MANAGER WORKFLOW ---
################################################################################


def direct_tunnel_workflow():
    """Entry point for the Direct Tunnel management menu."""

    # --- Helper functions specific to Direct Tunnels ---
    def load_direct_tunnels():
        if not os.path.exists(DIRECT_TUNNELS_DB_FILE):
            return {}
        os.makedirs(os.path.dirname(DIRECT_TUNNELS_DB_FILE), exist_ok=True)
        try:
            with open(DIRECT_TUNNELS_DB_FILE, 'r') as f:
                content = f.read()
                if not content:
                    return {}
                return json.loads(content)
        except (json.JSONDecodeError, FileNotFoundError):
            return {}

    def save_direct_tunnels(tunnels):
        os.makedirs(os.path.dirname(DIRECT_TUNNELS_DB_FILE), exist_ok=True)
        with open(DIRECT_TUNNELS_DB_FILE, 'w') as f:
            json.dump(tunnels, f, indent=4)
        print(f"\n{C.GREEN}Direct Tunnel configuration saved.{C.END}")

    def check_direct_port_conflicts(ports_to_check, other_tunnel_ports=None):
        system_used_ports = set()
        for proto_flag in ['-tlnp', '-ulnp']:
            result = run_command(['ss', proto_flag], capture=True)
            if result:
                for line in result.stdout.splitlines()[1:]:
                    match = re.search(r':(\d+)\s', line)
                    if match:
                        system_used_ports.add(int(match.group(1)))

        system_conflicts = ports_to_check.intersection(system_used_ports)
        if system_conflicts:
            ports_str = ', '.join(map(str, sorted(system_conflicts)))
            print(f"{C.RED}Error: Port(s) {ports_str} are in use by another system service.{C.END}")
            return False

        if other_tunnel_ports:
            tunnel_conflicts = ports_to_check.intersection(other_tunnel_ports)
            if tunnel_conflicts:
                ports_str = ', '.join(map(str, sorted(tunnel_conflicts)))
                print(f"{C.RED}Error: Port(s) {ports_str} are used by another direct tunnel.{C.END}")
                return False
        return True

    def generate_direct_rules(new_ports=None):
        tunnels = load_direct_tunnels()
        os.makedirs(os.path.dirname(DIRECT_TUNNEL_RULES_FILE), exist_ok=True)
        if not tunnels:
            if os.path.exists(DIRECT_TUNNEL_RULES_FILE):
                os.remove(DIRECT_TUNNEL_RULES_FILE)
            run_command(['systemctl', 'reload-or-restart', 'nftables'])
            return

        interface_cmd = "ip -4 route ls | grep default | grep -Po '(?<=dev )(\\S+)'"
        public_interface = subprocess.getoutput(interface_cmd).strip()
        if not public_interface:
            print(f"{C.RED}Error: Could not determine default public interface.{C.END}")
            return

        prerouting_rules, unique_foreign_ips = [], set()
        for tunnel in tunnels.values():
            foreign_ip, ports = tunnel['foreign_ip'], tunnel['ports']
            prerouting_rules.append(f"iif {public_interface} tcp dport {{ {ports} }} dnat ip to {foreign_ip}")
            prerouting_rules.append(f"iif {public_interface} udp dport {{ {ports} }} dnat ip to {foreign_ip}")
            unique_foreign_ips.add(foreign_ip)

        postrouting_rules = [f"ip daddr {ip} oif {public_interface} masquerade" for ip in unique_foreign_ips]
        prerouting_str = "\n\t\t".join(prerouting_rules)
        postrouting_str = "\n\t\t".join(postrouting_rules)

        rules_content = [
            f"# Direct NAT rules generated by Tunnel Manager v{VERSION}", "",
            "table inet direct_tunnel_nat {",
            f"\tchain prerouting {{ type nat hook prerouting priority dstnat; policy accept;\n\t\t{prerouting_str}\n\t}}",
            f"\tchain postrouting {{ type nat hook postrouting priority srcnat; policy accept;\n\t\t{postrouting_str}\n\t}}",
            "}"
        ]
        with open(DIRECT_TUNNEL_RULES_FILE, 'w') as f:
            f.write("\n".join(rules_content))

        print(f"{C.CYAN}Applying changes to nftables service...{C.END}")
        if run_command(['systemctl', 'reload-or-restart', 'nftables']):
            print(f"{C.GREEN}Direct NAT rules applied successfully.{C.END}")
            if new_ports:
                print(f"\n{C.BOLD}{C.YELLOW}--- ACTION REQUIRED ---")
                warning_msg = (
                    f"If you are running a firewall (like ufw, firewalld, or iptables), "
                    f"you MUST open port(s) {C.GREEN}{new_ports}{C.YELLOW} in its INPUT "
                    f"and FORWARD chains to allow traffic.{C.END}"
                )
                print(warning_msg)
        else:
            print(f"{C.RED}Failed to apply rules. Check 'systemctl status nftables' for errors.{C.END}")

    # --- Menu functions for Direct Tunnels ---
    def add_direct_tunnel():
        tunnels = load_direct_tunnels()
        name = input(f"{C.CYAN}Enter a unique name for the direct tunnel: {C.END}").strip()
        if not name or name in tunnels:
            print(f"{C.RED}Error: Name is invalid or already exists.{C.END}")
            return
        foreign_ip = input(f"{C.CYAN}Enter the destination server IP: {C.END}").strip()
        if not is_valid_ip(foreign_ip):
            print(f"{C.RED}Error: Invalid IP address format.{C.END}")
            return
        ports_str = input(f"{C.CYAN}Enter ports to forward (e.g., 80,443,1000-2000): {C.END}").strip()
        new_ports = parse_ports_to_set(ports_str)
        if new_ports is None or not new_ports:
            print(f"{C.RED}Error: Invalid or empty port format specified.{C.END}")
            return

        all_tunnel_ports = set()
        for tunnel in tunnels.values():
            ports = parse_ports_to_set(tunnel['ports'])
            if ports:
                all_tunnel_ports.update(ports)

        if not check_direct_port_conflicts(new_ports, other_tunnel_ports=all_tunnel_ports):
            return

        tunnels[name] = {'foreign_ip': foreign_ip, 'ports': ports_str}
        save_direct_tunnels(tunnels)
        generate_direct_rules(new_ports=ports_str)

    def list_direct_tunnels():
        tunnels = load_direct_tunnels()
        if not tunnels:
            print(f"\n{C.YELLOW}No direct tunnels are configured.{C.END}")
            return
        print(f"\n{C.HEADER}--- Configured Direct Tunnels ---{C.END}")
        for name, details in sorted(tunnels.items()):
            print(f"  {C.BOLD}{C.BLUE}Name:           {name}{C.END}")
            print(f"  {C.CYAN}Forwarding Ports: {details['ports']}")
            print(f"  {C.CYAN}To Server IP:     {details['foreign_ip']}{C.END}")
            print(f"{C.HEADER}-----------------------------------{C.END}")

    # --- Main loop for the Direct Tunnel menu ---
    while True:
        clear_screen()
        print(f"\n{C.HEADER}--- Direct NAT Tunnel Manager ---{C.END}")
        print(f"{C.GREEN}1. Add New Direct Tunnel")
        print(f"{C.BLUE}2. List All Direct Tunnels")
        print(f"{C.YELLOW}3. (Edit not implemented)")
        print(f"{C.RED}4. (Remove not implemented)")
        print(f"{C.CYAN}5. Re-apply All Rules")
        print(f"{C.YELLOW}6. Return to Main Menu{C.END}")
        choice = input("Enter your choice: ").strip()

        if choice == '1':
            add_direct_tunnel()
        elif choice == '2':
            list_direct_tunnels()
        elif choice == '5':
            generate_direct_rules()
        elif choice == '6':
            break
        else:
            print(f"{C.RED}Invalid choice.{C.END}")

        if choice in ['1', '2', '5']:
            press_enter_to_continue()


################################################################################
# --- REVERSE TUNNEL MANAGER WORKFLOW ---
################################################################################


def reverse_tunnel_workflow():
    """Entry point for the Reverse Tunnel management menu."""
    RECEIVED_KEY = None

    class KeyRegistrationHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            nonlocal RECEIVED_KEY
            if self.path == '/register':
                try:
                    content_length = int(self.headers['Content-Length'])
                    post_data = self.rfile.read(content_length)
                    data = json.loads(post_data)
                    pubkey = data.get('pubkey')
                    if pubkey and re.match(r'^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$', pubkey):
                        RECEIVED_KEY = pubkey
                        self.send_response(200)
                        self.end_headers()
                        self.wfile.write(b'OK')
                    else:
                        self.send_response(400)
                        self.end_headers()
                except Exception:
                    self.send_response(500)
                    self.end_headers()
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, format, *args):
            return  # Suppress logging

    def run_temp_server(server_holder):
        nonlocal RECEIVED_KEY
        try:
            server = HTTPServer(('', CALLBACK_PORT), KeyRegistrationHandler)
            server_holder.append(server)
            server.serve_forever()
        except Exception:
            RECEIVED_KEY = "SERVER_ERROR"

    def get_public_ip():
        print(f"{C.CYAN}Detecting public IP...{C.END}")
        for service in ["ifconfig.me/ip", "api.ipify.org", "icanhazip.com"]:
            result = run_command(['curl', '-s', '--connect-timeout', '5', service], use_sudo=False)
            if result and result.stdout and is_valid_ip(result.stdout.strip()):
                ip = result.stdout.strip()
                print(f"{C.GREEN}Detected public IP: {ip}{C.END}")
                return ip
        while True:
            prompt = (f"{C.RED}Could not auto-detect IP.{C.CYAN} "
                      f"Please enter public IP manually: {C.END}")
            manual_ip = input(prompt).strip()
            if is_valid_ip(manual_ip):
                return manual_ip

    def get_next_available_ip():
        try:
            if not os.path.exists(WG_CONFIG_FILE):
                return "10.0.0.2"
            with open(WG_CONFIG_FILE, 'r') as f:
                content = f.read()
            ips_in_use = re.findall(r'10\.0\.0\.(\d+)', content)
            used_octets = {int(octet) for octet in ips_in_use}
            next_octet = 2
            while next_octet in used_octets:
                next_octet += 1
            if next_octet > 254:
                return None
            return f"10.0.0.{next_octet}"
        except Exception as e:
            print(f"{C.RED}Error reading WireGuard config: {e}{C.END}")
            return None

    def load_peers():
        try:
            with open(REVERSE_PEERS_DB_FILE, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {}

    def save_peers(peers):
        os.makedirs(REVERSE_DB_DIR, exist_ok=True)
        with open(REVERSE_PEERS_DB_FILE, 'w') as f:
            json.dump(peers, f, indent=4)

    def initial_relay_setup():
        clear_screen()
        print(f"{C.HEADER}--- Initial WireGuard Endpoint Setup ---{C.END}")
        if os.path.exists(WG_CONFIG_FILE):
            prompt = (f"{C.YELLOW}Config already exists. Overwrite? "
                      f"(This removes all peers): {C.END}")
            choice = input(prompt).lower().strip()
            if choice != 'y':
                return

        server_b_privkey = run_command(['wg', 'genkey'], use_sudo=False).stdout.strip()
        wg_conf = (
            f"[Interface]\n# Endpoint Server Config\n"
            f"PrivateKey = {server_b_privkey}\n"
            f"Address = 10.0.0.1/24\n"
            f"ListenPort = 51820\n"
        )
        os.makedirs(os.path.dirname(WG_CONFIG_FILE), exist_ok=True)
        with open(WG_CONFIG_FILE, 'w') as f:
            f.write(wg_conf)
        os.chmod(WG_CONFIG_FILE, 0o600)

        if os.path.exists(REVERSE_PEERS_DB_FILE):
            os.remove(REVERSE_PEERS_DB_FILE)
        if os.path.exists(REVERSE_TUNNELS_DB_FILE):
            os.remove(REVERSE_TUNNELS_DB_FILE)

        run_command(['wg-quick', 'down', 'wg0'])
        run_command(['wg-quick', 'up', 'wg0'])
        run_command(['systemctl', 'enable', 'wg-quick@wg0'])
        print(f"\n{C.BOLD}{C.GREEN}--- Endpoint Setup Complete ---{C.END}")
        print("You can now add client peers.")
        press_enter_to_continue()

    def add_new_peer():
        nonlocal RECEIVED_KEY
        RECEIVED_KEY = None
        clear_screen()
        print(f"{C.HEADER}--- Add New Client Peer ---{C.END}")

        peer_ip_to_add = get_next_available_ip()
        if not peer_ip_to_add:
            print(f"{C.RED}Error: Could not assign a new IP. Subnet may be full.{C.END}")
            return

        print(f"{C.CYAN}Assigning new peer the IP address: {peer_ip_to_add}{C.END}")
        server_b_pubkey = run_command(['wg', 'show', 'wg0', 'public-key']).stdout.strip()
        server_b_public_ip = get_public_ip()
        if not server_b_public_ip:
            return

        server_holder = []
        server_thread = threading.Thread(target=run_temp_server, args=(server_holder,))
        server_thread.daemon = True
        server_thread.start()
        time.sleep(1)

        if RECEIVED_KEY == "SERVER_ERROR":
            print(f"{C.RED}Could not start registration server on port {CALLBACK_PORT}.{C.END}")
            return

        callback_url = f"http://{server_b_public_ip}:{CALLBACK_PORT}/register"
        setup_cmd = (
            f'curl -fsSL "{SCRIPT_URL}?cachebust=$(date +%s)" | sudo python3 - setup_client '
            f'--server-pubkey "{server_b_pubkey}" '
            f'--server-endpoint "{server_b_public_ip}:51820" '
            f'--callback-url "{callback_url}" '
            f'--client-ip "{peer_ip_to_add}"'
        )

        print(f"\n{C.BOLD}{C.YELLOW}--- ACTION REQUIRED on the new Client Server ---{C.END}")
        print("Run this full command on the new client. This script will wait.")
        print(f"\n{C.CYAN}{setup_cmd}{C.END}\n")
        print(f"{C.YELLOW}Waiting for new client to register... (Timeout: 2 minutes){C.END}")

        for _ in range(120):
            if RECEIVED_KEY:
                break
            time.sleep(1)

        if server_holder:
            server_holder[0].shutdown()

        if not RECEIVED_KEY or RECEIVED_KEY == "SERVER_ERROR":
            print(f"\n{C.RED}Timeout or server error. No key received.{C.END}")
            return

        prompt = "Enter a descriptive name for this new peer (e.g., germany-1): "
        peer_name = input(prompt).strip() or f"Peer-{peer_ip_to_add}"
        peer_conf = f"\n[Peer]\n# {peer_name}\nPublicKey = {RECEIVED_KEY}\nAllowedIPs = {peer_ip_to_add}/32\n"

        with open(WG_CONFIG_FILE, 'a') as f:
            f.write(peer_conf)

        peers = load_peers()
        peers[peer_name] = {'ip': peer_ip_to_add, 'pubkey': RECEIVED_KEY}
        save_peers(peers)

        print(f"{C.GREEN}New peer '{peer_name}' saved.{C.END}")
        run_command(['wg', 'set', 'wg0', 'peer', RECEIVED_KEY, 'allowed-ips', f'{peer_ip_to_add}/32'])
        print(f"\n{C.BOLD}{C.GREEN}--- New Peer Added Successfully ---{C.END}")

    is_setup = os.path.exists(WG_CONFIG_FILE)
    while True:
        clear_screen()
        print(f"\n{C.HEADER}--- Reverse WireGuard Tunnel Manager ---{C.END}")

        if not is_setup:
            print(f"{C.YELLOW}1. Initial Endpoint Setup (Run this once!){C.END}")
        else:
            print(f"{C.BLUE}1. Add New Client Peer{C.END}")

        print(f"\n{C.GREEN}--- Forwarding Rules (Not Implemented) ---{C.END}")
        print(f"{C.GREEN}2. Add Forwarding Rule")
        print(f"{C.CYAN}3. List Rules")
        print(f"{C.YELLOW}4. Edit Rule")
        print(f"{C.RED}5. Remove Rule")

        print(f"\n{C.YELLOW}--- System ---{C.END}")
        print(f"{C.YELLOW}6. Re-apply All Rules")
        print(f"{C.YELLOW}7. Uninstall")
        print(f"{C.YELLOW}8. Return to Main Menu{C.END}")

        choice = input("\nEnter your choice: ").strip()

        if choice == '1':
            if not is_setup:
                initial_relay_setup()
                is_setup = True
            else:
                add_new_peer()
        elif choice == '8':
            break
        else:
            print(f"{C.RED}Option not implemented yet.{C.END}")

        press_enter_to_continue()


################################################################################
# --- CLIENT SETUP LOGIC (invoked by command line arguments) ---
################################################################################

def setup_wireguard_client(server_pubkey, server_endpoint, callback_url, client_ip):
    clear_screen()
    print(f"{C.HEADER}--- Setting up WireGuard Client ---{C.END}")

    print(f"{C.YELLOW}Cleaning up any previous configurations...{C.END}")
    run_command(['wg-quick', 'down', 'wg0'])
    if os.path.exists(WG_CONFIG_FILE):
        os.remove(WG_CONFIG_FILE)

    server_a_privkey = run_command(['wg', 'genkey'], use_sudo=False).stdout.strip()
    server_a_pubkey = run_command(['wg', 'pubkey'], command_input=server_a_privkey).stdout.strip()

    wg_conf = (
        f"[Interface]\n# Client Server Config\n"
        f"PrivateKey = {server_a_privkey}\n"
        f"Address = {client_ip}/24\n\n"
        f"[Peer]\n# Endpoint Server\n"
        f"PublicKey = {server_pubkey}\n"
        f"Endpoint = {server_endpoint}\n"
        f"AllowedIPs = 10.0.0.0/24\n"
        f"PersistentKeepalive = 25\n"
    )

    os.makedirs(os.path.dirname(WG_CONFIG_FILE), exist_ok=True)
    with open(WG_CONFIG_FILE, 'w') as f:
        f.write(wg_conf)
    os.chmod(WG_CONFIG_FILE, 0o600)

    print(f"{C.GREEN}Generated WireGuard config with IP {client_ip}.{C.END}")
    print(f"{C.CYAN}Registering public key with endpoint server...{C.END}")

    payload = json.dumps({'pubkey': server_a_pubkey})
    cmd = ['curl', '-s', '-X', 'POST', '-H', 'Content-Type: application/json',
           '--data-raw', payload, callback_url]
    reg_result = run_command(cmd, use_sudo=False)

    if not reg_result or reg_result.stdout.strip() != 'OK':
        print(f"\n{C.RED}--- FAILED TO REGISTER WITH ENDPOINT ---{C.END}")
        sys.exit(1)

    print(f"{C.GREEN}Registration successful!{C.END}")
    run_command(['wg-quick', 'up', 'wg0'])
    run_command(['systemctl', 'enable', 'wg-quick@wg0'])
    print(f"\n{C.BOLD}{C.GREEN}--- CLIENT SETUP COMPLETE ---{C.END}")
    print("Tunnel is active.")
    sys.exit(0)


################################################################################
# --- TOP-LEVEL SCRIPT EXECUTION ---
################################################################################

def main():
    """The new top-level menu to route the user."""
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('command', nargs='?')
    parser.add_argument('--server-pubkey')
    parser.add_argument('--server-endpoint')
    parser.add_argument('--callback-url')
    parser.add_argument('--client-ip')

    if 'setup_client' in sys.argv:
        args = parser.parse_args()
        if (args.command == 'setup_client' and
                all([args.server_pubkey, args.server_endpoint,
                     args.callback_url, args.client_ip])):
            if os.geteuid() != 0:
                sys.exit(f"{C.RED}Client setup requires root privileges. Please run with sudo.{C.END}")
            ensure_dependencies({'wireguard': 'wg', 'curl': 'curl'})
            setup_wireguard_client(args.server_pubkey, args.server_endpoint,
                                   args.callback_url, args.client_ip)
        return

    if os.geteuid() != 0:
        sys.exit(f"{C.RED}This script requires root privileges. Please run with sudo.{C.END}")

    ensure_dependencies({'nftables': 'nft', 'curl': 'curl', 'wireguard': 'wg'})
    ensure_ip_forwarding()
    ensure_nftables_service()
    ensure_include_line()

    while True:
        clear_screen()
        print(f"{C.HEADER}===== Ultimate Tunnel Manager v{VERSION} =====")
        print("Please choose the type of tunnel to manage:")
        print(f"{C.GREEN}1. Manage Direct NAT Tunnels (Port Forwarding)")
        print(f"{C.CYAN}2. Manage Reverse WireGuard Tunnels (Endpoint)")
        print(f"{C.YELLOW}3. Exit{C.END}")
        choice = input("Enter your choice: ").strip()

        if choice == '1':
            direct_tunnel_workflow()
        elif choice == '2':
            reverse_tunnel_workflow()
        elif choice == '3':
            print("Exiting.")
            break
        else:
            print(f"{C.RED}Invalid choice. Please try again.{C.END}")
            time.sleep(2)


if __name__ == '__main__':
    main()
