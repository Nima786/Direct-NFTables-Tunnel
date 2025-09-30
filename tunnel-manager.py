#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Ultimate Tunnel Manager
Version: 2.0.0

This script combines a direct NAT/port forwarding manager and a
WireGuard-based reverse tunnel manager into a single, comprehensive tool.
"""

import os
import sys
import json
import subprocess
import shutil
import re
import argparse
import threading
import time
import socket
from http.server import BaseHTTPRequestHandler, HTTPServer

# --- Shared Configuration & Constants ---
SCRIPT_VERSION = "2.0.0"
# Correct URL for the client setup command
REVERSE_TUNNEL_SCRIPT_URL = "https://raw.githubusercontent.com/Nima786/Direct-NFTables-Tunnel/main/tunnel-manager"


# --- Color Codes ---
class C:
    """A simple class for ANSI color codes."""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'


# --- Shared Helper Functions ---
def clear_screen():
    """Clears the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')


def press_enter_to_continue():
    """Pauses execution until the user presses Enter."""
    input(f"\n{C.YELLOW}Press Enter to return to the menu...{C.END}")


def run_command(command, use_sudo=True, capture=True, text=True, shell=False, command_input=None):
    """
    Runs a shell command with sudo privileges, capturing output.
    Returns the result object on success, None on failure.
    """
    if use_sudo and os.geteuid() != 0:
        if shell:
            command = f'sudo {command}'
        else:
            command = ['sudo'] + command
    try:
        return subprocess.run(
            command,
            check=True,
            capture_output=capture,
            text=text,
            shell=shell,
            input=command_input
        )
    except subprocess.CalledProcessError as e:
        print(f"\n{C.RED}Error executing command: {command}{C.END}")
        if e.stderr:
            print(f"{C.RED}Stderr: {e.stderr.strip()}{C.END}")
        return None


def is_valid_ip(ip_str):
    """Checks if a string is a valid IPv4 address using the socket library."""
    try:
        socket.inet_aton(ip_str)
        return True
    except socket.error:
        return False


def parse_ports(ports_str):
    """
    Parses a string of ports (e.g., "80,443,1000-2000") into a
    comma-separated string and a set of integers for validation.
    Returns a tuple (formatted_string, port_set) or (None, None) on error.
    """
    ports = set()
    formatted_parts = []
    if not ports_str:
        return None, None
    try:
        for part in ports_str.split(','):
            part = part.strip()
            if not part:
                continue
            if '-' in part:
                start, end = map(int, part.split('-'))
                if not (0 < start <= 65535 and 0 < end <= 65535 and start < end):
                    return None, None
                ports.update(range(start, end + 1))
                formatted_parts.append(f"{start}-{end}")
            else:
                port = int(part)
                if not (0 < port <= 65535):
                    return None, None
                ports.add(port)
                formatted_parts.append(str(port))
        return ", ".join(formatted_parts), ports
    except ValueError:
        return None, None


def ensure_dependencies(packages):
    """
    Checks for required packages and prompts to install them if missing.
    `packages` should be a dict like {'package_name': 'command_to_check'}.
    """
    needs_install = [pkg for pkg, cmd in packages.items() if not shutil.which(cmd)]
    if needs_install:
        print(f"{C.YELLOW}Missing dependencies: {', '.join(needs_install)}. Attempting to install...{C.END}")
        if run_command(['apt-get', 'update', '-y'], capture=False) is None:
            print(f"{C.RED}Failed to update package lists.{C.END}")
            return False
        for pkg in needs_install:
            if run_command(['apt-get', 'install', pkg, '-y'], capture=False) is None:
                print(f"{C.RED}Failed to install {pkg}. Please install it manually.{C.END}")
                return False
        print(f"{C.GREEN}Dependencies installed successfully.{C.END}")
    return True


def ensure_ip_forwarding():
    """Ensures that IPv4 forwarding is enabled and persists across reboots."""
    result = run_command(['sysctl', 'net.ipv4.ip_forward'], capture=True)
    if result and 'net.ipv4.ip_forward = 1' in result.stdout:
        return
    print(f"{C.YELLOW}Enabling IP forwarding...{C.END}")
    if run_command(['sysctl', '-w', 'net.ipv4.ip_forward=1']) is None:
        print(f"{C.RED}Failed to enable IP forwarding dynamically.{C.END}")
        return

    try:
        with open('/etc/sysctl.conf', 'r+') as f:
            content = f.read()
            if 'net.ipv4.ip_forward=1' not in content:
                f.write('\n# Enabled by Ultimate Tunnel Manager\nnet.ipv4.ip_forward=1\n')
            elif '#net.ipv4.ip_forward=1' in content:
                content = content.replace('#net.ipv4.ip_forward=1', 'net.ipv4.ip_forward=1')
                f.seek(0)
                f.write(content)
                f.truncate()
        run_command(['sysctl', '-p'])
        print(f"{C.GREEN}IP forwarding enabled persistently.{C.END}")
    except IOError as e:
        print(f"{C.RED}Error updating /etc/sysctl.conf: {e}{C.END}")
        print(f"{C.YELLOW}IP forwarding will not be persistent.{C.END}")


def ensure_include_line(main_nft_config, rules_dir, manager_name):
    """Ensures the main nftables.conf includes the rules directory."""
    include_line = f'include "{rules_dir}/*.nft"'
    if not os.path.exists(main_nft_config):
        print(f"{C.YELLOW}Main config {main_nft_config} not found. Creating a default config...{C.END}")
        default_config = f"#!/usr/sbin/nft -f\nflush ruleset\n\n# Added by {manager_name}\n{include_line}\n"
        try:
            with open(main_nft_config, 'w') as f:
                f.write(default_config)
            print(f"{C.GREEN}Default config created successfully.{C.END}")
            return True
        except IOError as e:
            print(f"{C.RED}Failed to create default config: {e}{C.END}")
            return False

    try:
        with open(main_nft_config, 'r') as f:
            if include_line in f.read():
                return True
    except IOError as e:
        print(f"{C.RED}Could not read {main_nft_config}: {e}{C.END}")
        return False

    print(f"\n{C.YELLOW}The main nftables config is missing the required include line.{C.END}")
    try:
        with open(main_nft_config, 'a') as f:
            f.write(f"\n# Added by {manager_name}\n{include_line}\n")
        print(f"{C.GREEN}Successfully added include line to {main_nft_config}.{C.END}")
        return True
    except IOError as e:
        print(f"{C.RED}Error: Could not write to {main_nft_config}. Please add the line manually: {e}{C.END}")
        print(f"    {C.GREEN}{include_line}{C.END}")
        return False


def apply_nftables_config():
    """Reloads or restarts the nftables service to apply new rules."""
    print(f"{C.CYAN}Applying changes to nftables service...{C.END}")
    if run_command(['systemctl', 'reload', 'nftables']) is not None:
        print(f"{C.GREEN}nftables reloaded successfully.{C.END}")
        return True
    print(f"{C.YELLOW}Reload failed, attempting to restart...{C.END}")
    if run_command(['systemctl', 'restart', 'nftables']) is not None:
        print(f"{C.GREEN}nftables restarted successfully.{C.END}")
        return True
    print(f"{C.RED}Failed to apply nftables rules. Check 'systemctl status nftables'.{C.END}")
    return False


def load_json_db(db_file):
    """Loads a JSON database file, handling errors gracefully."""
    if not os.path.exists(db_file):
        return {}
    try:
        with open(db_file, 'r') as f:
            content = f.read()
            return json.loads(content) if content else {}
    except (json.JSONDecodeError, FileNotFoundError, PermissionError) as e:
        print(f"{C.RED}Warning: Could not load database {db_file}. Reason: {e}{C.END}")
        return {}


def save_json_db(db_file, data):
    """Saves data to a JSON database file."""
    try:
        dir_name = os.path.dirname(db_file)
        if not os.path.exists(dir_name):
            os.makedirs(dir_name, 0o755)
        with open(db_file, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"\n{C.GREEN}Configuration saved to {db_file}.{C.END}")
        return True
    except (IOError, PermissionError) as e:
        print(f"{C.RED}Error saving configuration to {db_file}. Reason: {e}{C.END}")
        return False


# ############################################################################
# --- DIRECT NAT TUNNEL MANAGER ---
# ############################################################################

class DirectTunnelManager:
    """Manages direct NAT port forwarding rules using nftables."""

    def __init__(self):
        self.db_file = '/etc/tunnel_manager/tunnels.json'
        self.rules_file = '/etc/nftables.d/direct-tunnel-manager.nft'
        self.nft_table_name = 'direct_tunnel_manager_nat'
        self.main_nft_config = '/etc/nftables.conf'
        self.rules_dir = '/etc/nftables.d'
        self.manager_name = "Direct Tunnel Manager"

    def check_port_conflicts(self, ports_to_check, tunnels, tunnel_to_ignore=None):
        """Checks for port conflicts against system services and other tunnels."""
        # 1. Check against system ports
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
            print(f"{C.RED}Error: Port(s) {sorted(list(system_conflicts))} are in use by another service.{C.END}")
            return False

        # 2. Check against other tunnels
        other_tunnel_ports = set()
        for name, details in tunnels.items():
            if name != tunnel_to_ignore:
                _, ports = parse_ports(details.get('ports', ''))
                if ports:
                    other_tunnel_ports.update(ports)

        tunnel_conflicts = ports_to_check.intersection(other_tunnel_ports)
        if tunnel_conflicts:
            print(f"{C.RED}Error: Port(s) {sorted(list(tunnel_conflicts))} are used by another tunnel.{C.END}")
            return False

        return True

    def generate_and_apply_rules(self):
        """Generates the nftables rules file and reloads the service."""
        if not ensure_include_line(self.main_nft_config, self.rules_dir, self.manager_name):
            return

        tunnels = load_json_db(self.db_file)
        if not tunnels:
            if os.path.exists(self.rules_file):
                run_command(['rm', self.rules_file])
                print(f"{C.YELLOW}No tunnels configured. Removing old rules file.{C.END}")
            apply_nftables_config()
            return

        result = run_command("ip -4 route ls | grep default | grep -Po '(?<=dev )(\\S+)'", shell=True)
        public_interface = result.stdout.strip() if result else None
        if not public_interface:
            print(f"{C.RED}Error: Could not determine default public interface.{C.END}")
            return

        prerouting_rules = []
        unique_foreign_ips = set()

        for tunnel in tunnels.values():
            foreign_ip, ports_str = tunnel['foreign_ip'], tunnel['ports']
            if ports_str:
                prerouting_rules.append(f"iif {public_interface} tcp dport {{ {ports_str} }} dnat ip to {foreign_ip}")
                prerouting_rules.append(f"iif {public_interface} udp dport {{ {ports_str} }} dnat ip to {foreign_ip}")
                unique_foreign_ips.add(foreign_ip)

        postrouting_rules = [f"ip daddr {ip} oif {public_interface} masquerade" for ip in unique_foreign_ips]

        rules_content = [
            f"# NAT rules generated by {self.manager_name} v{SCRIPT_VERSION}",
            f"table inet {self.nft_table_name} {{",
            "\tchain prerouting {",
            "\t\ttype nat hook prerouting priority dstnat; policy accept;",
            "\t\t" + "\n\t\t".join(prerouting_rules),
            "\t}",
            "\tchain postrouting {",
            "\t\ttype nat hook postrouting priority srcnat; policy accept;",
            "\t\t" + "\n\t\t".join(postrouting_rules),
            "\t}",
            "}",
        ]
        try:
            with open(self.rules_file, 'w') as f:
                f.write("\n".join(rules_content))
            apply_nftables_config()
        except IOError as e:
            print(f"{C.RED}Error writing rules file {self.rules_file}: {e}{C.END}")

    def add_tunnel(self):
        """Adds a new direct NAT tunnel."""
        tunnels = load_json_db(self.db_file)
        name = input(f"{C.CYAN}Enter a unique name for the tunnel: {C.END}").strip()
        if not name:
            print(f"{C.RED}Error: Name cannot be empty.{C.END}")
            return
        if name in tunnels:
            print(f"{C.RED}Error: A tunnel with this name already exists.{C.END}")
            return

        foreign_ip = input(f"{C.CYAN}Enter the destination server IP: {C.END}").strip()
        if not is_valid_ip(foreign_ip):
            print(f"{C.RED}Error: Invalid IP address format.{C.END}")
            return

        ports_str = input(f"{C.CYAN}Enter ports to forward (e.g., 80,443,1000-2000): {C.END}").strip()
        formatted_ports, new_ports_set = parse_ports(ports_str)
        if not new_ports_set:
            print(f"{C.RED}Error: Invalid or empty port format specified.{C.END}")
            return

        if not self.check_port_conflicts(new_ports_set, tunnels):
            return

        tunnels[name] = {'foreign_ip': foreign_ip, 'ports': formatted_ports}
        if save_json_db(self.db_file, tunnels):
            self.generate_and_apply_rules()
            print(f"\n{C.BOLD}{C.YELLOW}--- ACTION REQUIRED ---")
            print(f"Remember to open port(s) {C.GREEN}{formatted_ports}{C.YELLOW} in your main firewall.{C.END}")

    def list_tunnels(self):
        """Lists all configured direct NAT tunnels."""
        tunnels = load_json_db(self.db_file)
        if not tunnels:
            print(f"\n{C.YELLOW}No direct tunnels are configured.{C.END}")
            return
        print(f"\n{C.HEADER}--- Configured Direct Tunnels ---{C.END}")
        for name, details in sorted(tunnels.items()):
            print(f"  {C.BOLD}{C.BLUE}Name:           {name}{C.END}")
            print(f"  {C.CYAN}Forwarding Ports: {details['ports']}")
            print(f"  {C.CYAN}To Server IP:     {details['foreign_ip']}{C.END}")
            print(f"{C.HEADER}-------------------------------{C.END}")

    def edit_tunnel(self):
        """Edits an existing direct NAT tunnel."""
        tunnels = load_json_db(self.db_file)
        if not tunnels:
            print(f"{C.YELLOW}There are no tunnels to edit.{C.END}")
            return
        print(f"\n{C.HEADER}--- Select a Tunnel to Edit ---{C.END}")
        tunnel_names = sorted(list(tunnels.keys()))
        for i, name in enumerate(tunnel_names, 1):
            print(f"{C.YELLOW}{i}. {name}{C.END}")
        try:
            choice = int(input(f"\n{C.CYAN}Enter number to edit (0 to cancel): {C.END}"))
            if choice == 0:
                return
            tunnel_to_edit = tunnel_names[choice - 1]
        except (ValueError, IndexError):
            print(f"{C.RED}Invalid selection.{C.END}")
            return

        current = tunnels[tunnel_to_edit]
        print(f"\nEditing tunnel: {C.BOLD}{tunnel_to_edit}{C.END} (Press Enter to keep current value)")

        new_ip = input(f"  Enter new destination IP [{current['foreign_ip']}]: ").strip() or current['foreign_ip']
        if not is_valid_ip(new_ip):
            print(f"{C.RED}Error: Invalid IP address format.{C.END}")
            return

        new_ports_str = input(f"  Enter new ports [{current['ports']}]: ").strip() or current['ports']
        formatted_ports, new_ports_set = parse_ports(new_ports_str)
        if not new_ports_set:
            print(f"{C.RED}Error: Invalid or empty port format specified.{C.END}")
            return

        if not self.check_port_conflicts(new_ports_set, tunnels, tunnel_to_ignore=tunnel_to_edit):
            return

        tunnels[tunnel_to_edit] = {'foreign_ip': new_ip, 'ports': formatted_ports}
        if save_json_db(self.db_file, tunnels):
            self.generate_and_apply_rules()

    def remove_tunnel(self):
        """Removes a direct NAT tunnel."""
        tunnels = load_json_db(self.db_file)
        if not tunnels:
            print(f"{C.YELLOW}There are no tunnels to remove.{C.END}")
            return
        print(f"\n{C.HEADER}--- Select a Tunnel to Remove ---{C.END}")
        tunnel_names = sorted(list(tunnels.keys()))
        for i, name in enumerate(tunnel_names, 1):
            print(f"{C.YELLOW}{i}. {name}{C.END}")
        try:
            choice = int(input(f"\n{C.CYAN}Enter number to remove (0 to cancel): {C.END}"))
            if choice == 0:
                return
            tunnel_to_remove = tunnel_names[choice - 1]
        except (ValueError, IndexError):
            print(f"{C.RED}Invalid selection.{C.END}")
            return

        del tunnels[tunnel_to_remove]
        if save_json_db(self.db_file, tunnels):
            self.generate_and_apply_rules()
            print(f"\n{C.GREEN}Tunnel '{tunnel_to_remove}' removed.{C.END}")

    def main_menu(self):
        """The main menu loop for the Direct Tunnel Manager."""
        ensure_dependencies({'nftables': 'nft'})
        ensure_ip_forwarding()
        while True:
            clear_screen()
            print(f"{C.HEADER}===== Direct NAT Tunnel Manager ====={C.END}")
            menu = {
                '1': ("Add New Tunnel", self.add_tunnel),
                '2': ("List All Tunnels", self.list_tunnels),
                '3': ("Edit Tunnel", self.edit_tunnel),
                '4': ("Remove Tunnel", self.remove_tunnel),
                '5': ("Re-apply All Rules", self.generate_and_apply_rules),
                '6': ("Return to Main Menu", "exit")
            }
            print(f"{C.GREEN}1. Add New Tunnel")
            print(f"{C.BLUE}2. List All Tunnels")
            print(f"{C.YELLOW}3. Edit Tunnel")
            print(f"{C.RED}4. Remove Tunnel")
            print(f"{C.CYAN}5. Re-apply All Rules")
            print(f"{C.CYAN}6. Return to Main Menu{C.END}")
            choice = input("\nEnter your choice: ").strip()

            if choice in menu:
                action = menu[choice][1]
                if action == "exit":
                    break
                action()
                press_enter_to_continue()
            else:
                print(f"{C.RED}Invalid choice.{C.END}")
                time.sleep(1)


# ############################################################################
# --- REVERSE WIREGUARD TUNNEL MANAGER ---
# ############################################################################
# Global vars for the callback server
RECEIVED_KEY = None


class KeyRegistrationHandler(BaseHTTPRequestHandler):
    """A simple HTTP handler to receive a public key from a new peer."""
    def do_POST(self):
        global RECEIVED_KEY
        if self.path == '/register':
            try:
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                data = json.loads(post_data)
                pubkey = data.get('pubkey')
                # Basic validation for a WireGuard public key
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


def run_temp_server(server_holder):
    """Runs the temporary HTTP server in a separate thread."""
    try:
        server = HTTPServer(('', 58080), KeyRegistrationHandler)
        server_holder.append(server)
        server.serve_forever()
    except Exception:
        global RECEIVED_KEY
        RECEIVED_KEY = "SERVER_ERROR"


class ReverseTunnelManager:
    """Manages a WireGuard-based reverse tunnel setup."""

    def __init__(self):
        self.db_dir = '/etc/reverse_tunnel_manager'
        self.peers_db_file = os.path.join(self.db_dir, 'peers.json')
        self.tunnels_db_file = os.path.join(self.db_dir, 'tunnels.json')
        self.rules_file = '/etc/nftables.d/reverse-tunnel-manager.nft'
        self.main_nft_config = '/etc/nftables.conf'
        self.rules_dir = '/etc/nftables.d'
        self.nft_table_name = 'reverse_tunnel_manager_nat'
        self.wg_config_file = '/etc/wireguard/wg0.conf'
        self.install_path = '/usr/local/bin/ultimate-tunnel-manager'
        self.manager_name = "Reverse Tunnel Manager"

    def get_public_ip(self):
        """Detects the server's public IP address."""
        print(f"{C.CYAN}Detecting public IP...{C.END}")
        for service in ["ifconfig.me/ip", "api.ipify.org", "icanhazip.com"]:
            result = run_command(['curl', '-s', '--connect-timeout', '5', service], use_sudo=False)
            if result and result.stdout and is_valid_ip(result.stdout.strip()):
                ip = result.stdout.strip()
                print(f"{C.GREEN}Detected public IP: {ip}{C.END}")
                return ip
        while True:
            manual_ip = input(f"{C.RED}Could not auto-detect IP. Please enter public IP manually: {C.END}").strip()
            if is_valid_ip(manual_ip):
                return manual_ip

    def get_next_available_ip(self):
        """Finds the next available IP in the 10.0.0.0/24 subnet for a new peer."""
        if not os.path.exists(self.wg_config_file):
            return "10.0.0.2"
        try:
            with open(self.wg_config_file, 'r') as f:
                content = f.read()
            ips_in_use = re.findall(r'10\.0\.0\.(\d+)', content)
            used_octets = {int(octet) for octet in ips_in_use}
            next_octet = 2
            while next_octet in used_octets:
                next_octet += 1
            if next_octet > 254:
                return None
            return f"10.0.0.{next_octet}"
        except IOError as e:
            print(f"{C.RED}Error reading WireGuard config: {e}{C.END}")
            return None

    def initial_relay_setup(self):
        """Performs the first-time setup for the WireGuard relay server."""
        clear_screen()
        print(f"{C.HEADER}--- Initial WireGuard Relay Setup ---{C.END}")
        if os.path.exists(self.wg_config_file):
            choice = input(f"{C.YELLOW}Config already exists. Overwrite? (This removes all peers): (y/N){C.END} ")
            if choice.lower().strip() != 'y':
                return
        if not ensure_dependencies({'wireguard': 'wg'}):
            return

        privkey_res = run_command(['wg', 'genkey'], use_sudo=False)
        if not privkey_res:
            return
        server_privkey = privkey_res.stdout.strip()

        wg_conf = (
            "[Interface]\n"
            "# Relay Server Config\n"
            f"PrivateKey = {server_privkey}\n"
            "Address = 10.0.0.1/24\n"
            "ListenPort = 51820\n"
        )
        os.makedirs(os.path.dirname(self.wg_config_file), exist_ok=True)
        try:
            with open(self.wg_config_file, 'w') as f:
                f.write(wg_conf)
            os.chmod(self.wg_config_file, 0o600)
        except IOError as e:
            print(f"{C.RED}Failed to write WireGuard config: {e}{C.END}")
            return

        for f in [self.peers_db_file, self.tunnels_db_file, self.rules_file]:
            if os.path.exists(f):
                os.remove(f)

        run_command(['wg-quick', 'down', 'wg0'])
        run_command(['wg-quick', 'up', 'wg0'])
        run_command(['systemctl', 'enable', 'wg-quick@wg0'])
        print(f"\n{C.BOLD}{C.GREEN}--- Relay Setup Complete ---{C.END}")
        print("You can now add new peer servers.")

    def add_new_peer(self):
        """Guides the user through adding a new WireGuard peer."""
        global RECEIVED_KEY
        RECEIVED_KEY = None
        clear_screen()
        print(f"{C.HEADER}--- Add New Peer Server ---{C.END}")

        next_ip = self.get_next_available_ip()
        if not next_ip:
            print(f"{C.RED}Error: Could not assign a new IP. Subnet may be full.{C.END}")
            return
        print(f"{C.CYAN}Assigning new peer the IP address: {next_ip}{C.END}")

        server_pubkey_res = run_command(['wg', 'show', 'wg0', 'public-key'])
        if not server_pubkey_res:
            print(f"{C.RED}Could not get WireGuard public key.{C.END}")
            return
        server_pubkey = server_pubkey_res.stdout.strip()
        server_public_ip = self.get_public_ip()
        if not server_public_ip:
            return

        server_holder = []
        server_thread = threading.Thread(target=run_temp_server, args=(server_holder,))
        server_thread.daemon = True
        server_thread.start()
        time.sleep(1)

        if RECEIVED_KEY == "SERVER_ERROR":
            print(f"{C.RED}Could not start registration server on port 58080. Is it in use?{C.END}")
            return

        callback_url = f"http://{server_public_ip}:58080/register"
        setup_cmd = (
            f"curl -fsSL \"{REVERSE_TUNNEL_SCRIPT_URL}?cb=$(date +%s)\" | sudo python3 - setup_client "
            f"--server-pubkey \"{server_pubkey}\" --server-endpoint \"{server_public_ip}:51820\" "
            f"--callback-url \"{callback_url}\" --client-ip \"{next_ip}\""
        )
        print(f"\n{C.BOLD}{C.YELLOW}--- ACTION REQUIRED on the new Peer Server ---{C.END}")
        print("Run this command on the new peer. This script will wait for 2 minutes.\n")
        print(f"{C.CYAN}{setup_cmd}{C.END}\n")
        print(f"{C.YELLOW}Waiting for new peer to register...{C.END}")

        for _ in range(120):
            if RECEIVED_KEY:
                break
            time.sleep(1)
        if server_holder:
            server_holder[0].shutdown()

        if not RECEIVED_KEY or RECEIVED_KEY == "SERVER_ERROR":
            print(f"\n{C.RED}Timeout or server error. No key received.{C.END}")
            return

        peer_name = input("Enter a descriptive name for this new peer (e.g., web-server-1): ").strip()
        if not peer_name:
            peer_name = f"Peer-{next_ip}"

        peer_conf = f"\n[Peer]\n# {peer_name}\nPublicKey = {RECEIVED_KEY}\nAllowedIPs = {next_ip}/32\n"
        with open(self.wg_config_file, 'a') as f:
            f.write(peer_conf)

        peers = load_json_db(self.peers_db_file)
        peers[peer_name] = {'ip': next_ip, 'pubkey': RECEIVED_KEY}
        save_json_db(self.peers_db_file, peers)

        run_command(['wg', 'set', 'wg0', 'peer', RECEIVED_KEY, 'allowed-ips', f'{next_ip}/32'])
        print(f"\n{C.BOLD}{C.GREEN}--- New Peer '{peer_name}' Added Successfully ---{C.END}")

    def remove_peer(self):
        """Removes a peer and its configuration."""
        peers = load_json_db(self.peers_db_file)
        if not peers:
            print(f"\n{C.YELLOW}No peers to remove.{C.END}")
            return
        print(f"\n{C.HEADER}--- Select a Peer to Remove ---{C.END}")
        peer_names = sorted(list(peers.keys()))
        for i, name in enumerate(peer_names, 1):
            print(f"{C.YELLOW}{i}. {name} ({peers[name]['ip']}){C.END}")

        try:
            choice = int(input(f"\nEnter number to remove (0 to cancel): {C.END}"))
            if choice == 0:
                return
            peer_to_remove_name = peer_names[choice - 1]
            peer_to_remove = peers[peer_to_remove_name]
        except (ValueError, IndexError):
            print(f"{C.RED}Invalid selection.{C.END}")
            return

        # 1. Remove from wg config file
        with open(self.wg_config_file, 'r') as f:
            lines = f.readlines()
        with open(self.wg_config_file, 'w') as f:
            skip = False
            for line in lines:
                if f"PublicKey = {peer_to_remove['pubkey']}" in line:
                    skip = True
                elif line.strip().startswith('[Peer]'):
                    skip = False
                if not skip:
                    f.write(line)
        print(f"{C.GREEN}Removed peer from WireGuard config file.{C.END}")

        # 2. Remove from live interface
        run_command(['wg', 'set', 'wg0', 'peer', peer_to_remove['pubkey'], 'remove'])
        print(f"{C.GREEN}Removed peer from live WireGuard interface.{C.END}")

        # 3. Remove from peers DB
        del peers[peer_to_remove_name]
        save_json_db(self.peers_db_file, peers)

        print(f"\n{C.YELLOW}Note: Tunnels pointing to this peer's IP ({peer_to_remove['ip']}) are now orphaned.{C.END}")
        print(f"{C.YELLOW}Please edit or remove them from the 'Forwarding Rules' menu.{C.END}")
        print(f"\n{C.BOLD}{C.GREEN}Peer '{peer_to_remove_name}' removed successfully.{C.END}")

    def generate_and_apply_rules(self):
        """Generates nftables rules for all reverse tunnels."""
        if not ensure_include_line(self.main_nft_config, self.rules_dir, self.manager_name):
            return

        tunnels = load_json_db(self.tunnels_db_file)
        if not tunnels:
            if os.path.exists(self.rules_file):
                run_command(['rm', self.rules_file])
            apply_nftables_config()
            return

        res = run_command("ip -o -4 route show to default | awk '{print $5}'", shell=True)
        public_interface = res.stdout.strip() if res else None
        if not public_interface:
            print(f"{C.RED}Error: Could not determine public interface.{C.END}")
            return

        rules = [
            f"# Rules generated by {self.manager_name} v{SCRIPT_VERSION}",
            f"table inet {self.nft_table_name} {{",
            "\tchain prerouting { type nat hook prerouting priority dstnat; policy accept; }",
            "\tchain postrouting { type nat hook postrouting priority srcnat; policy accept; }",
            "}"
        ]
        for tunnel in tunnels.values():
            ports = tunnel["ports"]
            dest_ip = tunnel["dest_ip"]
            rules.append(f'add rule inet {self.nft_table_name} prerouting iif "{public_interface}" tcp dport {{ {ports} }} dnat ip to {dest_ip}')
            rules.append(f'add rule inet {self.nft_table_name} prerouting iif "{public_interface}" udp dport {{ {ports} }} dnat ip to {dest_ip}')

        unique_dest_ips = {t['dest_ip'] for t in tunnels.values()}
        for dest_ip in unique_dest_ips:
            rules.append(f'add rule inet {self.nft_table_name} postrouting ip daddr {dest_ip} oif "wg0" masquerade')

        with open(self.rules_file, 'w') as f:
            f.write("\n".join(rules))
        apply_nftables_config()

    def add_tunnel(self):
        """Adds a new port forwarding rule for a peer."""
        peers = load_json_db(self.peers_db_file)
        if not peers:
            print(f"\n{C.RED}No peer servers are configured. Please add one first.{C.END}")
            return

        peer_names = list(peers.keys())
        print("\n--- Select a Peer Server to Forward To ---")
        for i, name in enumerate(peer_names, 1):
            print(f"{C.YELLOW}{i}. {name} ({peers[name]['ip']}){C.END}")
        try:
            choice = int(input("\nEnter number for the destination server (0 to cancel): "))
            if choice == 0:
                return
            selected_peer_name = peer_names[choice - 1]
            dest_ip = peers[selected_peer_name]['ip']
        except (ValueError, IndexError):
            print(f"{C.RED}Invalid selection.{C.END}")
            return

        tunnels = load_json_db(self.tunnels_db_file)
        name = input(f"\nEnter a unique name for this rule (e.g., {selected_peer_name}-web): ").strip()
        if not name or name in tunnels:
            print(f"{C.RED}Error: Name is empty or already exists.{C.END}")
            return

        ports_str = input(f"Enter public ports to forward to '{selected_peer_name}' (e.g., 80, 443): ").strip()
        formatted_ports, _ = parse_ports(ports_str)
        if not formatted_ports:
            print(f"{C.RED}Error: Invalid port format.{C.END}")
            return

        tunnels[name] = {'dest_ip': dest_ip, 'ports': formatted_ports, 'peer_name': selected_peer_name}
        if save_json_db(self.tunnels_db_file, tunnels):
            self.generate_and_apply_rules()

    def list_tunnels(self):
        """Lists all configured forwarding rules."""
        tunnels = load_json_db(self.tunnels_db_file)
        if not tunnels:
            print(f"\n{C.YELLOW}No reverse tunnel forwarding rules are configured.{C.END}")
            return
        print(f"\n{C.HEADER}--- Configured Forwarding Rules ---{C.END}")
        for name, details in sorted(tunnels.items()):
            peer = details.get('peer_name', 'Unknown Peer')
            print(f"  {C.BOLD}{C.BLUE}Rule Name: {name}{C.END}")
            print(f"  {C.CYAN}Public Ports: {details['ports']}")
            print(f"  {C.CYAN}Forward To:   {peer} ({details['dest_ip']}){C.END}")
            print(f"{C.HEADER}-----------------------------------{C.END}")

    def edit_tunnel(self):
        """Edits an existing forwarding rule."""
        tunnels = load_json_db(self.tunnels_db_file)
        if not tunnels:
            print(f"\n{C.YELLOW}No rules to edit.{C.END}")
            return

        names = sorted(list(tunnels.keys()))
        print("\n--- Select a Rule to Edit ---")
        for i, name in enumerate(names, 1):
            print(f"{C.YELLOW}{i}. {name}{C.END}")
        try:
            choice = int(input(f"\nEnter number to edit (0 to cancel): {C.END}"))
            if choice == 0:
                return
            old_name = names[choice - 1]
        except (ValueError, IndexError):
            print(f"{C.RED}Invalid selection.{C.END}")
            return

        current = tunnels[old_name]
        print(f"\nEditing '{C.BOLD}{old_name}{C.END}'. Press Enter to keep current value.")
        new_name = input(f"  Enter new name [{old_name}]: ").strip() or old_name
        if new_name != old_name and new_name in tunnels:
            print(f"{C.RED}Error: Rule name '{new_name}' already exists.{C.END}")
            return

        new_ports_str = input(f"  Enter new ports [{current['ports']}]: ").strip() or current['ports']
        formatted_ports, _ = parse_ports(new_ports_str)
        if not formatted_ports:
            print(f"{C.RED}Error: Invalid port format.{C.END}")
            return

        # The destination IP and peer name are tied to the peer and shouldn't be edited here.
        # If a change is needed, the rule should be re-created for a different peer.
        del tunnels[old_name]
        tunnels[new_name] = {'dest_ip': current['dest_ip'], 'ports': formatted_ports, 'peer_name': current['peer_name']}
        if save_json_db(self.tunnels_db_file, tunnels):
            self.generate_and_apply_rules()
            print(f"{C.GREEN}Rule successfully updated.{C.END}")

    def remove_tunnel(self):
        """Removes a forwarding rule."""
        tunnels = load_json_db(self.tunnels_db_file)
        if not tunnels:
            print(f"\n{C.YELLOW}No rules to remove.{C.END}")
            return
        names = sorted(list(tunnels.keys()))
        print("\n--- Select a Rule to Remove ---")
        for i, name in enumerate(names, 1):
            print(f"{C.YELLOW}{i}. {name}{C.END}")
        try:
            choice = int(input(f"\nEnter number to remove (0 to cancel): {C.END}"))
            if choice > 0 and choice <= len(names):
                name_to_remove = names[choice - 1]
                del tunnels[name_to_remove]
                if save_json_db(self.tunnels_db_file, tunnels):
                    self.generate_and_apply_rules()
                    print(f"\n{C.GREEN}Rule '{name_to_remove}' removed.{C.END}")
        except (ValueError, IndexError):
            print(f"{C.RED}Invalid selection.{C.END}")

    def install(self):
        """Installs the script to a system path."""
        if os.path.exists(self.install_path):
            print(f"{C.YELLOW}Script is already installed at {self.install_path}.{C.END}")
            return
        print(f"{C.YELLOW}Installing to {self.install_path}...{C.END}")
        try:
            shutil.copy2(sys.argv[0], self.install_path)
            os.chmod(self.install_path, 0o755)
            print(f"{C.GREEN}Installation successful! Run with: {C.BOLD}sudo {os.path.basename(self.install_path)}{C.END}")
        except Exception as e:
            print(f"{C.RED}Installation failed: {e}{C.END}")

    def uninstall(self):
        """Removes the script and all its configurations."""
        print(f"{C.RED}{C.BOLD}This will remove the script, all databases, nftables rules, and the WireGuard config.{C.END}")
        choice = input(f"{C.RED}Are you sure you want to continue? (y/N): {C.END}")
        if choice.lower().strip() != 'y':
            print("Uninstall aborted.")
            return

        run_command(['wg-quick', 'down', 'wg0'])
        for path in [self.install_path, self.db_dir, self.rules_file, self.wg_config_file]:
            if os.path.exists(path):
                try:
                    if os.path.isdir(path):
                        shutil.rmtree(path)
                    else:
                        os.remove(path)
                    print(f"{C.GREEN}Removed {path}.{C.END}")
                except OSError as e:
                    print(f"{C.RED}Failed to remove {path}: {e}{C.END}")
        apply_nftables_config()
        print(f"\n{C.GREEN}Uninstallation complete.{C.END}")

    def main_menu(self):
        """The main menu loop for the Reverse Tunnel Manager."""
        deps = {'nftables': 'nft', 'curl': 'curl', 'wireguard': 'wg', 'gawk': 'awk'}
        ensure_dependencies(deps)
        ensure_ip_forwarding()

        is_setup = os.path.exists(self.wg_config_file)

        while True:
            clear_screen()
            print(f"{C.HEADER}===== Reverse Tunnel Manager {SCRIPT_VERSION} ====={C.END}")
            # Refresh setup status
            is_setup = os.path.exists(self.wg_config_file)

            if not is_setup:
                print(f"{C.YELLOW}WireGuard relay has not been set up yet.{C.END}")
                menu = {'1': ("Initial Relay Setup (Run this first!)", self.initial_relay_setup)}
            else:
                print(f"{C.BLUE}--- WireGuard Management ---{C.END}")
                menu = {
                    '1': ("Add New Peer Server", self.add_new_peer),
                    '2': ("Remove Peer Server", self.remove_peer)
                }
                print(f"{C.BLUE}1. Add New Peer Server")
                print(f"{C.RED}2. Remove Peer Server{C.END}")
                print(f"\n{C.GREEN}--- Forwarding Rules ---{C.END}")
                menu.update({
                    '3': ("Add New Forwarding Rule", self.add_tunnel),
                    '4': ("List All Forwarding Rules", self.list_tunnels),
                    '5': ("Edit Forwarding Rule", self.edit_tunnel),
                    '6': ("Remove Forwarding Rule", self.remove_tunnel)
                })
                print(f"{C.GREEN}3. Add New Forwarding Rule")
                print(f"{C.CYAN}4. List All Forwarding Rules")
                print(f"{C.YELLOW}5. Edit Forwarding Rule")
                print(f"{C.RED}6. Remove Forwarding Rule{C.END}")

            print(f"\n{C.YELLOW}--- System ---{C.END}")
            menu.update({
                '7': ("Re-apply All Rules", self.generate_and_apply_rules),
                '8': ("Uninstall", self.uninstall),
                '9': ("Return to Main Menu", "exit")
            })
            print(f"{C.YELLOW}7. Re-apply All Rules")
            print(f"{C.YELLOW}8. Uninstall")
            print(f"{C.YELLOW}9. Return to Main Menu{C.END}")

            choice = input("\nEnter your choice: ").strip()
            if choice in menu:
                action = menu[choice][1]
                if action == "exit":
                    break
                action()
                if action == self.uninstall:  # Exit after uninstall
                    break
                press_enter_to_continue()
            else:
                print(f"{C.RED}Invalid choice.{C.END}")
                time.sleep(1)


def setup_wireguard_client(server_pubkey, server_endpoint, callback_url, client_ip):
    """
    This function is executed on the client machine via the one-line setup command.
    """
    print(f"{C.HEADER}--- Setting up WireGuard Client for Reverse Tunnel ---{C.END}")
    if os.geteuid() != 0:
        sys.exit(f"{C.RED}This action requires root privileges. Please run with sudo.{C.END}")
    if not ensure_dependencies({'wireguard': 'wg', 'curl': 'curl'}):
        sys.exit(1)

    print(f"{C.YELLOW}Cleaning up any previous configurations...{C.END}")
    run_command(['wg-quick', 'down', 'wg0'])
    wg_config_file = '/etc/wireguard/wg0.conf'
    if os.path.exists(wg_config_file):
        os.remove(wg_config_file)

    client_privkey = run_command(['wg', 'genkey'], use_sudo=False).stdout.strip()
    client_pubkey = run_command(['wg', 'pubkey'], command_input=client_privkey).stdout.strip()
    wg_conf = (
        "[Interface]\n"
        "# Client Server Config\n"
        f"PrivateKey = {client_privkey}\n"
        f"Address = {client_ip}/24\n\n"
        "[Peer]\n"
        "# Relay Server\n"
        f"PublicKey = {server_pubkey}\n"
        f"Endpoint = {server_endpoint}\n"
        "AllowedIPs = 10.0.0.0/24\n"
        "PersistentKeepalive = 25\n"
    )
    os.makedirs(os.path.dirname(wg_config_file), exist_ok=True)
    with open(wg_config_file, 'w') as f:
        f.write(wg_conf)
    os.chmod(wg_config_file, 0o600)
    print(f"{C.GREEN}Generated WireGuard config with IP {client_ip}.{C.END}")

    print(f"{C.CYAN}Registering public key with relay server...{C.END}")
    payload = json.dumps({'pubkey': client_pubkey})
    cmd = ['curl', '-s', '-X', 'POST', '-H', 'Content-Type: application/json', '--data-raw', payload, callback_url]
    reg_result = run_command(cmd, use_sudo=False)

    if not reg_result or reg_result.stdout.strip() != 'OK':
        print(f"\n{C.RED}--- FAILED TO REGISTER WITH RELAY ---{C.END}")
        print("Please check the relay server output and network connectivity.")
        sys.exit(1)

    print(f"{C.GREEN}Registration successful!{C.END}")
    run_command(['wg-quick', 'up', 'wg0'])
    run_command(['systemctl', 'enable', 'wg-quick@wg0'])
    print(f"\n{C.BOLD}{C.GREEN}--- SETUP COMPLETE ---{C.END}\nTunnel is active.")
    sys.exit(0)


# ############################################################################
# --- MAIN SCRIPT EXECUTION ---
# ############################################################################

def main():
    """The main entry point for the Ultimate Tunnel Manager."""
    # Handle client-side setup argument first
    parser = argparse.ArgumentParser(description="Ultimate Tunnel Manager", add_help=False)
    parser.add_argument('command', nargs='?')
    parser.add_argument('--server-pubkey')
    parser.add_argument('--server-endpoint')
    parser.add_argument('--callback-url')
    parser.add_argument('--client-ip')
    if 'setup_client' in sys.argv:
        args = parser.parse_args()
        if all([args.server_pubkey, args.server_endpoint, args.callback_url, args.client_ip]):
            setup_wireguard_client(
                args.server_pubkey, args.server_endpoint,
                args.callback_url, args.client_ip
            )
            return

    # Proceed with the main menu if not a client setup
    if os.geteuid() != 0:
        sys.exit(f"{C.RED}This script requires root privileges. Please run with sudo.{C.END}")

    # Handle one-time installation prompt
    install_path = '/usr/local/bin/ultimate-tunnel-manager'
    if not os.path.exists(install_path) and sys.argv[0] != install_path:
        choice = input(f"{C.HEADER}Install Ultimate Tunnel Manager to {install_path}? (Y/n): {C.END}")
        if choice.lower().strip() in ['y', '']:
            ReverseTunnelManager().install()
            print(f"{C.GREEN}Please run the script again using 'sudo ultimate-tunnel-manager'.{C.END}")
        return

    direct_manager = DirectTunnelManager()
    reverse_manager = ReverseTunnelManager()

    while True:
        clear_screen()
        print(f"{C.HEADER}======== Ultimate Tunnel Manager v{SCRIPT_VERSION} ========{C.END}")
        print(f"{C.CYAN}Please choose which manager to use:{C.END}")
        print(f"{C.BLUE}1. Manage Direct NAT Tunnels")
        print(f"{C.GREEN}2. Manage Reverse WireGuard Tunnels")
        print(f"{C.YELLOW}3. Exit{C.END}")
        choice = input("\nEnter your choice: ").strip()

        if choice == '1':
            direct_manager.main_menu()
        elif choice == '2':
            reverse_manager.main_menu()
        elif choice == '3':
            print("Exiting.")
            break
        else:
            print(f"{C.RED}Invalid choice.{C.END}")
            time.sleep(1)


if __name__ == '__main__':
    main()
