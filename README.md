🚀 NFTables Tunnel Manager
==========================

A simple, powerful, and lightweight menu-driven script to create and manage direct TCP/UDP tunnels on Ubuntu servers using `nftables`. This tool is ideal for high-performance port forwarding without the overhead of a full VPN or proxy.

✨ Features
----------

*   ⚡️ **High Performance:** Forwards packets at the kernel level for maximum speed and minimal latency.
*   🪶 **Lightweight:** No background daemons or extra services. Uses the kernel's built-in `nftables` framework.
*   😎 **User-Friendly:** A simple menu-driven interface to add, list, edit, and remove tunnels.
*   ⚙️ **Flexible:** Supports single ports, comma-separated lists of ports, and port ranges.
*   🛡️ **Safe:** Includes checks for port conflicts and ensures system configurations are handled safely.

⚙️ How It Works
---------------

This script acts as a user-friendly manager for `nftables` NAT rules. It allows you to take incoming traffic on a specific port on your server (Server B) and forward it directly to another server (Server A).

This is a **direct tunnel**, meaning the connection is initiated by the end-user to your public server (Server B).

🚀 Quick Run & Installation
---------------------------

You can run the script with a single command without any permanent installation. This is a great way to try it out.

    sudo bash -c "python3 <(curl -fsSL https://raw.githubusercontent.com/Nima786/Direct-NFTables-Tunnel/main/tunnel-manager.py)"

The first time you run this, the script will present you with a simple setup menu:

    ===== Welcome to Tunnel Manager Setup =====
    1. Install
    2. Exit
    Enter choice:
    

If you choose **Install**, the script will copy itself to `/usr/local/bin/tunnel-manager`, so you can run it from anywhere on your system in the future.

⌨️ Usage
--------

After installation, you can run the manager from any directory by simply typing:

    sudo tunnel-manager

This will bring up the main menu, allowing you to manage your tunnels.

### ⚠️ Important Note for Firewall Users

This script is designed to only manage its own NAT rules. It **does not** manage your main firewall's filter rules.

For a tunnel to work, you **must** manually open the necessary ports in your firewall's `INPUT` and `FORWARD` chains. The script will remind you of this and provide example commands each time you add or edit a tunnel.

📄 License
----------

This project is licensed under the MIT License.
