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
VERSION = '3.0.0'

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
SCRIPT_URL = "https://raw.githubusercontent.com/Nima786/Direct-NFTables-Tunnel/main/tunnel-manager"

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
    pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    if not pattern.match(ip_str):
        return False
    parts = ip_str.split('.')
    for item in parts:
        if not 0 <= int(item) <= 255:
            return False
    return True


def parse_ports_to_set(ports_str):
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
    needs_install = [pkg for pkg, cmd in packages.items() if not shutil.which(cmd)]
    if needs_install:
        print(f"{C.YELLOW}Missing dependencies: {', '.join(needs_install)}. Attempting to install...{C.END}")
        run_command(['apt-get', 'update', '-y'], capture=False)
        for pkg in needs_install:
            if not run_command(['apt-get', 'install', '-y', pkg], capture=False):
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
    include_line = 'include "/etc/nftables.d/*.nft"'
    if not os.path.exists(MAIN_NFT_CONFIG):
        with open(MAIN_NFT_CONFIG, 'w') as f:
            f.write(f"#!/usr/sbin/nft -f\nflush ruleset\n\n{include_line}\n")
        return
    with open(MAIN_NFT_CONFIG, 'r+') as f:
        content = f.read()
        if include_line not in content:
            f.write(f"\n# Added by Ultimate Tunnel Manager\n{include_line}\n")


################################################################################
# --- DIRECT TUNNEL MANAGER WORKFLOW ---
################################################################################

def direct_tunnel_workflow():
    """Entry point for the Direct Tunnel management menu."""

    def load_direct_tunnels():
        os.makedirs(os.path.dirname(DIRECT_TUNNELS_DB_FILE), exist_ok=True)
        try:
            with open(DIRECT_TUNNELS_DB_FILE, 'r') as f:
                content = f.read()
                return json.loads(content) if content else {}
        except (json.JSONDecodeError, FileNotFoundError):
            return {}

    def save_direct_tunnels(tunnels):
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
            print(f"{C.RED}Error: Port(s) {sorted(list(system_conflicts))} are in use by another system service.{C.END}")
            return False
        if other_tunnel_ports:
            tunnel_conflicts = ports_to_check.intersection(other_tunnel_ports)
            if tunnel_conflicts:
                print(f"{C.RED}Error: Port(s) {sorted(list(tunnel_conflicts))} are used by another direct tunnel.{C.END}")
                return False
        return True

    def generate_direct_rules(new_ports_str=None):
        tunnels = load_direct_tunnels()
        if not tunnels:
            if os.path.exists(DIRECT_TUNNEL_RULES_FILE):
                os.remove(DIRECT_TUNNEL_RULES_FILE)
            run_command(['systemctl', 'reload-or-restart', 'nftables'])
            print(f"{C.YELLOW}No direct tunnels. Rules cleared.{C.END}")
            return
        interface = subprocess.getoutput("ip -4 route ls | grep default | grep -Po '(?<=dev )(\\S+)'").strip()
        prerouting, unique_ips = [], set()
        for t in tunnels.values():
            prerouting.append(f"iif {interface} tcp dport {{ {t['ports']} }} dnat ip to {t['foreign_ip']}")
            prerouting.append(f"iif {interface} udp dport {{ {t['ports']} }} dnat ip to {t['foreign_ip']}")
            unique_ips.add(t['foreign_ip'])
        postrouting = [f"ip daddr {ip} oif {interface} masquerade" for ip in unique_ips]
        prerouting_str = "\n\t\t".join(prerouting)
        postrouting_str = "\n\t\t".join(postrouting)
        rules = [
            f"# Direct NAT rules v{VERSION}", "", "table inet direct_nat {",
            (f"\tchain prerouting {{ type nat hook prerouting priority dstnat; "
             f"policy accept;\n\t\t{prerouting_str}\n\t}}"),
            (f"\tchain postrouting {{ type nat hook postrouting priority srcnat; "
             f"policy accept;\n\t\t{postrouting_str}\n\t}}"),
            "}"
        ]
        with open(DIRECT_TUNNEL_RULES_FILE, 'w') as f:
            f.write('\n'.join(rules))
        if run_command(['systemctl', 'reload-or-restart', 'nftables']):
            print(f"{C.GREEN}Direct NAT rules applied.{C.END}")
            if new_ports_str:
                print(f"\n{C.BOLD}{C.YELLOW}--- ACTION REQUIRED ---")
                print(f"If running a firewall, you MUST open port(s) {C.GREEN}{new_ports_str}{C.YELLOW} to allow traffic.{C.END}")
        else:
            print(f"{C.RED}Failed to apply rules.{C.END}")

    def add_direct_tunnel():
        tunnels = load_direct_tunnels()
        name = input(f"{C.CYAN}Enter a unique name: {C.END}").strip()
        if not name or name in tunnels:
            print(f"{C.RED}Error: Name invalid or exists.{C.END}"); return
        ip = input(f"{C.CYAN}Enter destination IP: {C.END}").strip()
        if not is_valid_ip(ip):
            print(f"{C.RED}Error: Invalid IP.{C.END}"); return
        ports_str = input(f"{C.CYAN}Enter ports (e.g., 80,443,1000-2000): {C.END}").strip()
        new_ports = parse_ports_to_set(ports_str)
        if not new_ports:
            print(f"{C.RED}Error: Invalid ports.{C.END}"); return
        all_ports = {p for t in tunnels.values() for p in parse_ports_to_set(t['ports'])}
        if not check_direct_port_conflicts(new_ports, other_tunnel_ports=all_ports):
            return
        tunnels[name] = {'foreign_ip': ip, 'ports': ports_str}
        save_direct_tunnels(tunnels)
        generate_direct_rules(ports_str)

    def list_direct_tunnels():
        tunnels = load_direct_tunnels()
        if not tunnels:
            print(f"\n{C.YELLOW}No tunnels configured.{C.END}"); return
        print(f"\n{C.HEADER}--- Configured Direct Tunnels ---{C.END}")
        for n, d in sorted(tunnels.items()):
            print(f" {C.BOLD}{C.BLUE}{n}{C.END}: Ports {C.CYAN}{d['ports']}{C.END} -> {C.CYAN}{d['foreign_ip']}{C.END}")

    def edit_direct_tunnel():
        tunnels = load_direct_tunnels()
        if not tunnels:
            print(f"\n{C.YELLOW}No tunnels to edit.{C.END}"); return
        names = sorted(tunnels.keys())
        for i, name in enumerate(names, 1):
            print(f"{i}. {name}")
        try:
            choice = int(input("Enter number to edit (0 to cancel): "))
            if choice == 0:
                return
            old_name = names[choice - 1]
            current = tunnels[old_name]
            print(f"\nEditing '{old_name}'. Press Enter to keep current value.")
            new_name = input(f" New name [{old_name}]: ").strip() or old_name
            if new_name != old_name and new_name in tunnels:
                print(f"{C.RED}Error: Name '{new_name}' already exists.{C.END}"); return
            new_ip = input(f" New destination IP [{current['foreign_ip']}]: ").strip() or current['foreign_ip']
            if not is_valid_ip(new_ip):
                print(f"{C.RED}Error: Invalid IP.{C.END}"); return
            new_ports_str = input(f" New ports [{current['ports']}]: ").strip() or current['ports']
            new_ports = parse_ports_to_set(new_ports_str)
            if not new_ports:
                print(f"{C.RED}Error: Invalid ports.{C.END}"); return
            other_ports = {p for n, t in tunnels.items() if n != old_name for p in parse_ports_to_set(t['ports'])}
            if not check_direct_port_conflicts(new_ports, other_tunnel_ports=other_ports):
                return
            del tunnels[old_name]
            tunnels[new_name] = {'foreign_ip': new_ip, 'ports': new_ports_str}
            save_direct_tunnels(tunnels)
            generate_direct_rules(new_ports_str)
        except (ValueError, IndexError):
            print(f"{C.RED}Invalid input.{C.END}")

    def remove_direct_tunnel():
        tunnels = load_direct_tunnels()
        if not tunnels:
            print(f"\n{C.YELLOW}No tunnels to remove.{C.END}"); return
        names = sorted(tunnels.keys())
        for i, name in enumerate(names, 1):
            print(f"{i}. {name}")
        try:
            choice = int(input("Enter number to remove (0 to cancel): "))
            if 0 < choice <= len(names):
                name_to_remove = names[choice - 1]
                del tunnels[name_to_remove]
                save_direct_tunnels(tunnels)
                generate_direct_rules()
                print(f"Tunnel '{name_to_remove}' removed.")
        except (ValueError, IndexError):
            print(f"{C.RED}Invalid input.{C.END}")

    while True:
        clear_screen()
        print(f"\n{C.HEADER}--- Direct NAT Tunnel Manager ---{C.END}")
        options = {"1": "Add", "2": "List", "3": "Edit", "4": "Remove", "5": "Re-apply Rules", "6": "Return to Main Menu"}
        for k, v in options.items():
            print(f"{k}. {v}")
        choice = input("Enter choice: ").strip()
        if choice == '1': add_direct_tunnel()
        elif choice == '2': list_direct_tunnels()
        elif choice == '3': edit_direct_tunnel()
        elif choice == '4': remove_direct_tunnel()
        elif choice == '5': generate_direct_rules()
        elif choice == '6': break
        else: print(f"{C.RED}Invalid choice.{C.END}")
        press_enter_to_continue()


################################################################################
# --- REVERSE TUNNEL MANAGER WORKFLOW ---
################################################################################

def reverse_tunnel_workflow():
    """Entry point for the Reverse Tunnel management menu."""
    RECEIVED_KEY = None

    class KeyRegHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            nonlocal RECEIVED_KEY
            try:
                data = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
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
        def log_message(self, format, *args):
            return

    def run_temp_server(holder):
        nonlocal RECEIVED_KEY
        try:
            holder.append(HTTPServer(('', CALLBACK_PORT), KeyRegHandler))
            holder[0].serve_forever()
        except Exception:
            RECEIVED_KEY = "SERVER_ERROR"

    def get_public_ip():
        for s in ["ifconfig.me/ip", "api.ipify.org"]:
            r = run_command(['curl', '-s', '--connect-timeout', '5', s], False)
            if r and r.stdout and is_valid_ip(r.stdout.strip()):
                return r.stdout.strip()
        while True:
            ip = input(f"{C.RED}Could not auto-detect IP. Enter manually: {C.END}").strip()
            if is_valid_ip(ip):
                return ip

    def get_next_wg_ip():
        if not os.path.exists(WG_CONFIG_FILE):
            return "10.0.0.2"
        with open(WG_CONFIG_FILE, 'r') as f:
            content = f.read()
        octets = {int(o) for o in re.findall(r'10\.0\.0\.(\d+)', content)}
        o = 2
        while o in octets:
            o += 1
        return f"10.0.0.{o}" if o <= 254 else None

    def load_peers():
        try:
            with open(REVERSE_PEERS_DB_FILE, 'r') as f:
                return json.load(f)
        except (IOError, json.JSONDecodeError):
            return {}

    def save_peers(peers):
        os.makedirs(REVERSE_DB_DIR, exist_ok=True)
        with open(REVERSE_PEERS_DB_FILE, 'w') as f:
            json.dump(peers, f, indent=4)

    def load_reverse_tunnels():
        try:
            with open(REVERSE_TUNNELS_DB_FILE, 'r') as f:
                return json.load(f)
        except (IOError, json.JSONDecodeError):
            return {}

    def save_reverse_tunnels(tunnels):
        os.makedirs(REVERSE_DB_DIR, exist_ok=True)
        with open(REVERSE_TUNNELS_DB_FILE, 'w') as f:
            json.dump(tunnels, f, indent=4)

    def initial_relay_setup():
        if os.path.exists(WG_CONFIG_FILE) and input("Overwrite existing WG config? (y/N): ").lower() != 'y':
            return
        privkey = run_command(['wg', 'genkey'], False).stdout.strip()
        conf = f"[Interface]\nPrivateKey = {privkey}\nAddress = 10.0.0.1/24\nListenPort = 51820\n"
        os.makedirs(os.path.dirname(WG_CONFIG_FILE), exist_ok=True)
        with open(WG_CONFIG_FILE, 'w') as f:
            f.write(conf)
        os.chmod(WG_CONFIG_FILE, 0o600)
        for f_path in [REVERSE_PEERS_DB_FILE, REVERSE_TUNNELS_DB_FILE, REVERSE_TUNNEL_RULES_FILE]:
            if os.path.exists(f_path):
                os.remove(f_path)
        run_command(['wg-quick', 'down', 'wg0'])
        run_command(['wg-quick', 'up', 'wg0'])
        run_command(['systemctl', 'enable', 'wg-quick@wg0'])
        print("Endpoint setup complete.")

    def add_new_peer():
        nonlocal RECEIVED_KEY
        RECEIVED_KEY = None
        ip = get_next_wg_ip()
        if not ip:
            print("Subnet full."); return
        pubkey = run_command(['wg', 'show', 'wg0', 'public-key']).stdout.strip()
        public_ip = get_public_ip()
        holder = []
        threading.Thread(target=run_temp_server, args=(holder,), daemon=True).start()
        time.sleep(1)
        if RECEIVED_KEY == "SERVER_ERROR":
            print("Could not start registration server."); return
        cmd = (f'curl -fsSL "{SCRIPT_URL}" | sudo python3 - setup_client '
               f'--server-pubkey "{pubkey}" --server-endpoint "{public_ip}:51820" '
               f'--callback-url "http://{public_ip}:{CALLBACK_PORT}/register" --client-ip "{ip}"')
        print(f"Run on client, this will wait:\n\n{C.CYAN}{cmd}{C.END}\n")
        for _ in range(120):
            if RECEIVED_KEY:
                break
            time.sleep(1)
        if holder:
            holder[0].shutdown()
        if not RECEIVED_KEY or RECEIVED_KEY == "SERVER_ERROR":
            print("Timeout or error."); return
        name = input("Enter peer name: ").strip() or f"Peer-{ip}"
        conf = f"\n[Peer]\n# {name}\nPublicKey = {RECEIVED_KEY}\nAllowedIPs = {ip}/32\n"
        with open(WG_CONFIG_FILE, 'a') as f:
            f.write(conf)
        peers = load_peers()
        peers[name] = {'ip': ip, 'pubkey': RECEIVED_KEY}
        save_peers(peers)
        run_command(['wg', 'set', 'wg0', 'peer', RECEIVED_KEY, 'allowed-ips', f'{ip}/32'])
        print("Peer added.")

    def remove_peer():
        peers = load_peers()
        if not peers:
            print("No peers to remove."); return
        names = sorted(peers.keys())
        for i, name in enumerate(names, 1):
            print(f"{i}. {name}")
        try:
            choice = int(input("Enter number to remove (0 to cancel): "))
            if 0 < choice <= len(names):
                name = names[choice - 1]
                pubkey = peers[name]['pubkey']
                with open(WG_CONFIG_FILE, "r") as f:
                    lines = f.readlines()
                in_peer_section = False
                with open(WG_CONFIG_FILE, "w") as f:
                    for line in lines:
                        if f"PublicKey = {pubkey}" in line:
                            in_peer_section = True
                            continue
                        if in_peer_section and line.strip() == "":
                            in_peer_section = False
                        if not in_peer_section:
                            f.write(line)
                run_command(['wg', 'set', 'wg0', 'peer', pubkey, 'remove'])
                del peers[name]
                save_peers(peers)
                print(f"Peer '{name}' removed.")
        except (ValueError, IndexError):
            print("Invalid input.")

    def add_reverse_tunnel():
        peers = load_peers()
        if not peers:
            print("No peers configured. Add a peer first."); return
        peer_names = sorted(peers.keys())
        for i, name in enumerate(peer_names, 1):
            print(f"{i}. {name} ({peers[name]['ip']})")
        try:
            choice = int(input("Select destination peer (0 to cancel): "))
            if choice == 0: return
            dest_ip = peers[peer_names[choice - 1]]['ip']
            tunnels = load_reverse_tunnels()
            name = input("Enter a unique name for this rule: ").strip()
            if not name or name in tunnels:
                print("Name invalid or exists."); return
            ports_str = input(f"Enter public ports to forward to {dest_ip}: ").strip()
            if not parse_ports_to_set(ports_str):
                print("Invalid port format."); return
            tunnels[name] = {'dest_ip': dest_ip, 'ports': ports_str}
            save_reverse_tunnels(tunnels)
            generate_reverse_rules()
        except (ValueError, IndexError):
            print("Invalid selection.")

    def generate_reverse_rules():
        tunnels = load_reverse_tunnels()
        if not tunnels:
            if os.path.exists(REVERSE_TUNNEL_RULES_FILE): os.remove(REVERSE_TUNNEL_RULES_FILE)
            run_command(['systemctl', 'reload-or-restart', 'nftables']); return
        interface = subprocess.getoutput("ip -4 route ls | grep default | grep -Po '(?<=dev )(\\S+)'").strip()
        rules = ["table inet reverse_nat {",
                 "\tchain prerouting { type nat hook prerouting priority dstnat; policy accept; }",
                 "\tchain postrouting { type nat hook postrouting priority srcnat; policy accept; }", "}"]
        for t in tunnels.values():
            rules.append(f'add rule inet reverse_nat prerouting iif "{interface}" tcp dport {{ {t["ports"]} }} dnat ip to {t["dest_ip"]}')
            rules.append(f'add rule inet reverse_nat prerouting iif "{interface}" udp dport {{ {t["ports"]} }} dnat ip to {t["dest_ip"]}')
        unique_dest_ips = {t['dest_ip'] for t in tunnels.values()}
        for dest_ip in unique_dest_ips:
            rules.append(f'add rule inet reverse_nat postrouting ip daddr {dest_ip} oif "wg0" masquerade')
        with open(REVERSE_TUNNEL_RULES_FILE, 'w') as f: f.write('\n'.join(rules))
        run_command(['systemctl', 'reload-or-restart', 'nftables'])
        print("Reverse tunnel rules applied.")
    
    def list_reverse_tunnels():
        tunnels = load_reverse_tunnels()
        if not tunnels: print(f"\n{C.YELLOW}No reverse tunnels configured.{C.END}"); return
        print(f"\n{C.HEADER}--- Configured Reverse Tunnels ---{C.END}")
        for n, d in sorted(tunnels.items()):
            print(f" {C.BOLD}{C.BLUE}{n}{C.END}: Ports {C.CYAN}{d['ports']}{C.END} -> {C.CYAN}{d['dest_ip']}{C.END}")
            
    def remove_reverse_tunnel():
        tunnels = load_reverse_tunnels()
        if not tunnels: print(f"\n{C.YELLOW}No tunnels to remove.{C.END}"); return
        names = sorted(tunnels.keys())
        for i, name in enumerate(names, 1): print(f"{i}. {name}")
        try:
            choice = int(input("Enter number to remove (0 to cancel): "))
            if 0 < choice <= len(names):
                del tunnels[names[choice - 1]]
                save_reverse_tunnels(tunnels); generate_reverse_rules()
        except (ValueError, IndexError): print(f"{C.RED}Invalid input.{C.END}")

    def uninstall_reverse_tunnel():
        if input("This will remove all configs. Are you sure? (y/N): ").lower() != 'y': return
        if os.path.exists(REVERSE_DB_DIR): shutil.rmtree(REVERSE_DB_DIR)
        if os.path.exists(REVERSE_TUNNEL_RULES_FILE): os.remove(REVERSE_TUNNEL_RULES_FILE)
        if os.path.exists(WG_CONFIG_FILE):
            run_command(['wg-quick', 'down', 'wg0']); os.remove(WG_CONFIG_FILE)
        generate_reverse_rules() # To clear rules
        print("Uninstallation complete.")

    is_setup = os.path.exists(WG_CONFIG_FILE)
    while True:
        clear_screen()
        print(f"\n{C.HEADER}--- Reverse WireGuard Tunnel Manager ---{C.END}")
        menu = {}
        if not is_setup:
            menu['1'] = ("Initial Endpoint Setup", initial_relay_setup)
        else:
            menu['1'] = ("Add New Peer", add_new_peer)
            menu['2'] = ("Remove Peer", remove_peer)
            menu['3'] = ("Add Forwarding Rule", add_reverse_tunnel)
            menu['4'] = ("List Forwarding Rules", list_reverse_tunnels)
            menu['5'] = ("Remove Forwarding Rule", remove_reverse_tunnel)
            menu['6'] = ("Re-apply All Rules", generate_reverse_rules)
            menu['7'] = ("Uninstall", uninstall_reverse_tunnel)
        menu['9'] = ("Return to Main Menu", "break")
        
        for key, (text, _) in menu.items(): print(f"{key}. {text}")
        choice = input("Enter choice: ").strip()
        action = menu.get(choice, [None, None])[1]

        if action == "break": break
        elif action:
            if choice == '7': action(); break
            else: action()
        else: print("Invalid choice.")
        press_enter_to_continue()


################################################################################
# --- CLIENT SETUP LOGIC ---
################################################################################

def setup_wireguard_client(server_pubkey, server_endpoint, callback_url, client_ip):
    run_command(['wg-quick', 'down', 'wg0'])
    if os.path.exists(WG_CONFIG_FILE):
        os.remove(WG_CONFIG_FILE)
    privkey = run_command(['wg', 'genkey'], False).stdout.strip()
    pubkey = run_command(['wg', 'pubkey'], command_input=privkey).stdout.strip()
    conf = (f"[Interface]\nPrivateKey = {privkey}\nAddress = {client_ip}/24\n\n"
            f"[Peer]\nPublicKey = {server_pubkey}\nEndpoint = {server_endpoint}\n"
            f"AllowedIPs = 10.0.0.0/24\nPersistentKeepalive = 25\n")
    os.makedirs(os.path.dirname(WG_CONFIG_FILE), exist_ok=True)
    with open(WG_CONFIG_FILE, 'w') as f:
        f.write(conf)
    os.chmod(WG_CONFIG_FILE, 0o600)
    payload = json.dumps({'pubkey': pubkey})
    cmd = ['curl', '-s', '-X', 'POST', '-H', 'Content-Type: application/json', '--data-raw', payload, callback_url]
    reg_result = run_command(cmd, False)
    if not reg_result or reg_result.stdout.strip() != 'OK':
        print("Failed to register with endpoint."); sys.exit(1)
    run_command(['wg-quick', 'up', 'wg0'])
    run_command(['systemctl', 'enable', 'wg-quick@wg0'])
    print("Client setup complete."); sys.exit(0)


################################################################################
# --- TOP-LEVEL SCRIPT EXECUTION ---
################################################################################

def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('command', nargs='?')
    parser.add_argument('--server-pubkey')
    parser.add_argument('--server-endpoint')
    parser.add_argument('--callback-url')
    parser.add_argument('--client-ip')
    if 'setup_client' in sys.argv:
        args = parser.parse_args()
        if (args.command == 'setup_client' and all([args.server_pubkey, args.server_endpoint, args.callback_url, args.client_ip])):
            if os.geteuid() != 0:
                sys.exit("Client setup requires root.")
            ensure_dependencies({'wireguard': 'wg', 'curl': 'curl'})
            setup_wireguard_client(args.server_pubkey, args.server_endpoint, args.callback_url, args.client_ip)
        return
    if os.geteuid() != 0:
        sys.exit("This script requires root privileges.")
    ensure_dependencies({'nftables': 'nft', 'curl': 'curl', 'wireguard': 'wg', 'gawk': 'awk'})
    ensure_ip_forwarding()
    ensure_nftables_service()
    ensure_include_line()
    while True:
        clear_screen()
        print(f"{C.HEADER}===== Ultimate Tunnel Manager v{VERSION} =====")
        print("1. Manage Direct NAT Tunnels")
        print("2. Manage Reverse WireGuard Tunnels")
        print("3. Exit")
        choice = input("Enter choice: ").strip()
        if choice == '1':
            direct_tunnel_workflow()
        elif choice == '2':
            reverse_tunnel_workflow()
        elif choice == '3':
            print("Exiting."); break
        else:
            print("Invalid choice."); time.sleep(1)


if __name__ == '__main__':
    main()
