#!/usr/bin/env python3
import os
import sys
import json
import subprocess
import shutil
import re

# --- Configuration ---
TUNNELS_DB_FILE = '/etc/tunnel_manager/tunnels.json'
TUNNEL_RULES_FILE = '/etc/nftables.d/tunnel-manager-nat.nft'
MAIN_NFT_CONFIG = '/etc/nftables.conf'
INSTALL_PATH = '/usr/local/bin/tunnel-manager'
NFT_NAT_TABLE_NAME = 'tunnel_manager_nat'


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


# --- Helper Functions ---
def clear_screen():
    os.system('clear')


def press_enter_to_continue():
    input(f"\n{C.YELLOW}Press Enter to return to the menu...{C.END}")


def run_command(command, use_sudo=True, capture=True):
    if use_sudo and os.geteuid() != 0:
        command = ['sudo'] + command
    try:
        return subprocess.run(
            command, check=True, capture_output=capture, text=True
        )
    except subprocess.CalledProcessError as e:
        print(f"\n{C.RED}Error executing command: {' '.join(command)}{C.END}")
        print(f"{C.RED}Stderr: {e.stderr.strip()}{C.END}")
        return None


def ensure_dependencies():
    if not shutil.which('nft'):
        print(f"{C.YELLOW}nftables not found. Attempting to install...{C.END}")
        if run_command(['apt', 'update', '-y']) and \
           run_command(['apt', 'install', 'nftables', '-y']):
            print(f"{C.GREEN}nftables installed successfully.{C.END}")
        else:
            print(
                f"{C.RED}Failed to install nftables. "
                f"Please install it manually.{C.END}"
            )
            sys.exit(1)


def enable_ip_forwarding():
    result = run_command(['sysctl', 'net.ipv4.ip_forward'], capture=True)
    if result and 'net.ipv4.ip_forward = 1' in result.stdout:
        return
    print(f"{C.YELLOW}Enabling IP forwarding...{C.END}")
    run_command(['sysctl', '-w', 'net.ipv4.ip_forward=1'])
    with open('/etc/sysctl.conf', 'r+') as f:
        content = f.read()
        if 'net.ipv4.ip_forward=1' not in content:
            f.write('\nnet.ipv4.ip_forward=1\n')
        elif '#net.ipv4.ip_forward=1' in content:
            content = content.replace(
                '#net.ipv4.ip_forward=1', 'net.ipv4.ip_forward=1'
            )
            f.seek(0)
            f.write(content)
            f.truncate()
    run_command(['sysctl', '-p'])
    print(f"{C.GREEN}IP forwarding enabled.{C.END}")


def load_tunnels():
    if not os.path.exists(TUNNELS_DB_FILE):
        return {}
    with open(TUNNELS_DB_FILE, 'r') as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}


def save_tunnels(tunnels):
    os.makedirs(os.path.dirname(TUNNELS_DB_FILE), exist_ok=True)
    with open(TUNNELS_DB_FILE, 'w') as f:
        json.dump(tunnels, f, indent=4)
    print(f"\n{C.GREEN}Tunnel configuration saved.{C.END}")


def check_port_conflicts(ports_str, existing_tunnel_ports=None):
    """Checks if any of the specified ports are already in use."""
    try:
        requested_ports = set()
        parts = ports_str.split(',')
        for part in parts:
            part = part.strip()
            if '-' in part:
                start, end = map(int, part.split('-'))
                requested_ports.update(range(start, end + 1))
            else:
                requested_ports.add(int(part))
    except ValueError:
        print(
            f"{C.RED}Error: Invalid port format. Please use numbers, "
            f"commas, or ranges (e.g., 80,443,1000-2000).{C.END}"
        )
        return False

    used_ports = set()
    for proto_flag in ['-tlnp', '-ulnp']:
        result = run_command(['ss', proto_flag], capture=True)
        if result:
            for line in result.stdout.splitlines()[1:]:
                match = re.search(r':(\d+)\s', line)
                if match:
                    used_ports.add(int(match.group(1)))

    if existing_tunnel_ports:
        used_ports -= existing_tunnel_ports

    conflicts = requested_ports.intersection(used_ports)
    if conflicts:
        print(
            f"{C.RED}Error: The following port(s) are already in use: "
            f"{', '.join(map(str, sorted(conflicts)))}{C.END}"
        )
        return False
    return True


def ensure_include_line():
    """Checks for the include line and asks to add it if missing."""
    include_line = 'include "/etc/nftables.d/*.nft"'
    if not os.path.exists(MAIN_NFT_CONFIG):
        print(
            f"{C.YELLOW}Main config {MAIN_NFT_CONFIG} not found. "
            f"Creating a default config...{C.END}"
        )
        default_config = ["#!/usr/sbin/nft -f", "flush ruleset", "", include_line]
        with open(MAIN_NFT_CONFIG, 'w') as f:
            f.write("\n".join(default_config))
        print(f"{C.GREEN}Default config created successfully.{C.END}")
        return True
    else:
        with open(MAIN_NFT_CONFIG, 'r') as f:
            if include_line in f.read():
                return True

        print(f"\n{C.BOLD}{C.YELLOW}--- CONFIGURATION MISMATCH ---{C.END}")
        print(
            f"Your main firewall file ({C.CYAN}{MAIN_NFT_CONFIG}{C.YELLOW}) "
            f"is missing the required include line."
        )
        choice = input(
            f"Add it automatically? ({C.GREEN}Y{C.END}/{C.RED}n{C.END}): "
        ).lower().strip()

        if choice == 'y' or choice == '':
            try:
                with open(MAIN_NFT_CONFIG, 'a') as f:
                    f.write(f"\n# Added by Tunnel Manager\n{include_line}\n")
                print(f"{C.GREEN}Successfully added the include line.{C.END}")
                return True
            except Exception as e:
                print(
                    f"{C.RED}Error: Could not write to {MAIN_NFT_CONFIG}. "
                    f"Please add the line manually. {e}{C.END}"
                )
                return False
        else:
            print(f"\n{C.BOLD}{C.RED}--- MANUAL ACTION REQUIRED ---")
            print(
                f"Please add the following line to the end of "
                f"{C.CYAN}{MAIN_NFT_CONFIG}{C.RED}:"
            )
            print(f"    {C.GREEN}{include_line}")
            print("\nThen, run this command to apply all changes:")
            print(f"    {C.GREEN}sudo systemctl reload nftables{C.END}")
            return False


def generate_and_apply_rules(new_ports=None):
    if not ensure_include_line():
        return

    tunnels = load_tunnels()
    os.makedirs(os.path.dirname(TUNNEL_RULES_FILE), exist_ok=True)

    if not tunnels:
        if os.path.exists(TUNNEL_RULES_FILE):
            os.remove(TUNNEL_RULES_FILE)
        print(f"{C.CYAN}Reloading nftables service...{C.END}")
        if run_command(['systemctl', 'reload', 'nftables']):
            print(f"{C.GREEN}Service reloaded successfully.{C.END}")
        else:
            print(f"{C.RED}Failed to reload nftables.{C.END}")
        return

    interface_cmd = "ip -4 route ls | grep default | grep -Po '(?<=dev )(\\S+)'"
    public_interface = subprocess.getoutput(interface_cmd).strip()
    if not public_interface:
        print(f"{C.RED}Error: Could not determine default interface.{C.END}")
        return

    prerouting_rules = []
    postrouting_rules = []

    for tunnel in tunnels.values():
        foreign_ip, ports = tunnel['foreign_ip'], tunnel['ports']
        prerouting_rules.append(
            f"iif {public_interface} tcp dport {{ {ports} }} "
            f"dnat ip to {foreign_ip}"
        )
        prerouting_rules.append(
            f"iif {public_interface} udp dport {{ {ports} }} "
            f"dnat ip to {foreign_ip}"
        )
        postrouting_rules.append(
            f"ip daddr {foreign_ip} oif {public_interface} masquerade"
        )

    prerouting_rules_str = "; ".join(prerouting_rules)
    postrouting_rules_str = "; ".join(postrouting_rules)

    rules_content = [
        "# NAT rules generated by Tunnel Manager", "",
        f"table inet {NFT_NAT_TABLE_NAME} {{",
        "\tchain prerouting {",
        "\t\ttype nat hook prerouting priority dstnat; policy accept;",
        f"\t\t{prerouting_rules_str};",
        "\t}",
        "\tchain postrouting {",
        "\t\ttype nat hook postrouting priority srcnat; policy accept;",
        f"\t\t{postrouting_rules_str};",
        "\t}",
        "}}",
    ]

    with open(TUNNEL_RULES_FILE, 'w') as f:
        f.write("\n".join(rules_content))

    print(f"{C.CYAN}Reloading nftables service to apply all rules...{C.END}")
    if run_command(['systemctl', 'reload', 'nftables']):
        print(f"{C.GREEN}NAT rules applied successfully.{C.END}")
        if new_ports:
            print(f"\n{C.BOLD}{C.YELLOW}--- ACTION REQUIRED ---")
            print(
                f"To allow traffic, you MUST open port(s) "
                f"{C.GREEN}{new_ports}{C.YELLOW} in your firewall's "
                f"INPUT and FORWARD chains.{C.END}"
            )
    else:
        print(
            f"{C.RED}Failed to reload nftables. "
            f"Check 'systemctl status nftables' for errors.{C.END}"
        )


# --- Menu Functions ---
def add_new_tunnel():
    tunnels = load_tunnels()
    name = input(f"{C.CYAN}Enter a unique name for the tunnel: {C.END}").strip()
    if not name or name in tunnels:
        print(f"{C.RED}Error: Name is empty or already exists.{C.END}")
        return
    foreign_ip = input(
        f"{C.CYAN}Enter the destination server IP: {C.END}"
    ).strip()
    ports = input(f"{C.CYAN}Enter ports to forward: {C.END}").strip()

    if not check_port_conflicts(ports):
        return

    tunnels[name] = {'foreign_ip': foreign_ip, 'ports': ports}
    save_tunnels(tunnels)
    generate_and_apply_rules(new_ports=ports)


def list_tunnels():
    tunnels = load_tunnels()
    if not tunnels:
        print(f"\n{C.YELLOW}No tunnels are configured.{C.END}")
        return
    print(f"\n{C.HEADER}--- Configured Tunnels ---{C.END}")
    for name, details in tunnels.items():
        print(f"  {C.BOLD}{C.BLUE}Name:           {name}{C.END}")
        print(f"  {C.CYAN}Forwarding Ports: {details['ports']}")
        print(f"  {C.CYAN}To Server IP:     {details['foreign_ip']}{C.END}")
        print(f"{C.HEADER}--------------------------{C.END}")


def edit_tunnel():
    tunnels = load_tunnels()
    if not tunnels:
        print(f"{C.YELLOW}There are no tunnels to edit.{C.END}")
        return
    print(f"\n{C.HEADER}--- Select a Tunnel to Edit ---{C.END}")
    tunnel_names = list(tunnels.keys())
    for i, name in enumerate(tunnel_names, 1):
        print(f"{C.YELLOW}{i}. {name}{C.END}")
    try:
        choice = int(input(
            f"\n{C.CYAN}Enter number to edit (0 to cancel): {C.END}"
        ))
        if choice == 0:
            return
        tunnel_to_edit = tunnel_names[choice - 1]
        current_details = tunnels[tunnel_to_edit]

        current_ports_set = set()
        parts = current_details['ports'].split(',')
        for part in parts:
            part = part.strip()
            if '-' in part:
                start, end = map(int, part.split('-'))
                current_ports_set.update(range(start, end + 1))
            else:
                current_ports_set.add(int(part))

        print(
            f"\nEditing tunnel: {C.BOLD}{tunnel_to_edit}{C.END}\n"
            f"(Press Enter to keep the current value)"
        )
        new_ip = input(
            f"  Enter new destination IP [{current_details['foreign_ip']}]: "
        ).strip() or current_details['foreign_ip']
        new_ports = input(
            f"  Enter new ports [{current_details['ports']}]: "
        ).strip() or current_details['ports']

        if new_ports != current_details['ports'] and not \
           check_port_conflicts(new_ports, existing_tunnel_ports=current_ports_set):
            return

        tunnels[tunnel_to_edit] = {'foreign_ip': new_ip, 'ports': new_ports}
        save_tunnels(tunnels)
        generate_and_apply_rules(new_ports=new_ports)
    except (ValueError, IndexError):
        print(f"{C.RED}Invalid selection.{C.END}")


def remove_tunnel():
    tunnels = load_tunnels()
    if not tunnels:
        print(f"{C.YELLOW}There are no tunnels to remove.{C.END}")
        return
    print(f"\n{C.HEADER}--- Select a Tunnel to Remove ---{C.END}")
    tunnel_names = list(tunnels.keys())
    for i, name in enumerate(tunnel_names, 1):
        print(f"{C.YELLOW}{i}. {name}{C.END}")
    try:
        choice = int(input(
            f"\n{C.CYAN}Enter number to remove (0 to cancel): {C.END}"
        ))
        if choice == 0:
            return
        tunnel_to_remove = tunnel_names[choice - 1]
        del tunnels[tunnel_to_remove]
        save_tunnels(tunnels)
        generate_and_apply_rules()
        print(f"\n{C.GREEN}Tunnel '{tunnel_to_remove}' removed.{C.END}")
    except (ValueError, IndexError):
        print(f"{C.RED}Invalid selection.{C.END}")


# --- Installation and Main Menu ---
def install():
    print(f"{C.YELLOW}Installing Tunnel Manager to {INSTALL_PATH}...{C.END}")
    try:
        shutil.copy2(sys.argv[0], INSTALL_PATH)
        os.chmod(INSTALL_PATH, 0o755)
        print(
            f"{C.GREEN}Installation successful! "
            f"Run with: {C.BOLD}sudo tunnel-manager{C.END}"
        )
        ensure_dependencies()
        enable_ip_forwarding()
    except Exception as e:
        print(f"{C.RED}Installation failed: {e}{C.END}")


def uninstall():
    if os.path.exists(INSTALL_PATH):
        os.remove(INSTALL_PATH)
    if os.path.exists(os.path.dirname(TUNNELS_DB_FILE)):
        shutil.rmtree(os.path.dirname(TUNNELS_DB_FILE))
    if os.path.exists(TUNNEL_RULES_FILE):
        os.remove(TUNNEL_RULES_FILE)
    print(f"{C.GREEN}Uninstallation complete.{C.END}")
    print("Restarting firewall to apply changes: ")
    run_command(['systemctl', 'restart', 'nftables'])


def main_menu():
    if os.geteuid() != 0:
        sys.exit(
            f"{C.RED}This script requires root privileges. "
            f"Please run with sudo.{C.END}"
        )
    if not os.path.exists(INSTALL_PATH):
        clear_screen()
        print(f"{C.HEADER}===== Welcome to Tunnel Manager Setup =====")
        choice = input(f"{C.CYAN}1. Install\n2. Exit\nEnter choice: {C.END}").strip()
        if choice == '1':
            install()
    else:
        while True:
            clear_screen()
            print(f"\n{C.HEADER}===== NFTables Tunnel Manager =====")
            print(f"{C.GREEN}1. Add New Tunnel")
            print(f"{C.BLUE}2. List All Tunnels")
            print(f"{C.YELLOW}3. Edit Tunnel")
            print(f"{C.RED}4. Remove Tunnel")
            print(f"{C.CYAN}5. Re-apply All Rules")
            print(f"{C.CYAN}6. Uninstall")
            print(f"{C.CYAN}7. Exit{C.END}")
            choice = input("Enter your choice: ").strip()

            if choice == '1':
                add_new_tunnel()
            elif choice == '2':
                list_tunnels()
            elif choice == '3':
                edit_tunnel()
            elif choice == '4':
                remove_tunnel()
            elif choice == '5':
                generate_and_apply_rules()
            elif choice == '6':
                uninstall()
                break
            elif choice == '7':
                print("Exiting.")
                break
            else:
                print(f"{C.RED}Invalid choice.{C.END}")

            if choice in ['1', '2', '3', '4', '5']:
                press_enter_to_continue()


if __name__ == '__main__':
    main_menu()
