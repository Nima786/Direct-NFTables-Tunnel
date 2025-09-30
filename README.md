🚀 Hyper-Route
==============

**A unified, menu-driven TUI for managing complex nftables forwarding rules. Hyper-Route simplifies both direct NAT (port forwarding) and WireGuard-based reverse tunnels, making advanced network routing accessible to everyone.**

Built with Python, Hyper-Route acts as a powerful configuration manager for `nftables`, writing clean, unified, and syntactically correct rulesets automatically. Whether you need to expose a local service or create a secure reverse tunnel for a server behind a firewall, Hyper-Route provides a simple, interactive workflow.

✨ Key Features
--------------

*   **Unified Management**: unified\_hub: Control both direct NAT and WireGuard reverse tunnels from a single, intuitive interface.
*   **🔢 Direct NAT Tunnels**: Easily create, list, edit, and remove port forwarding rules to expose services on your network.
*   **🛡️ WireGuard Reverse Tunnels**:
    *   Set up a central "Relay" server with a single command.
    *   Generate one-line setup commands to easily add new "Client" peers.
    *   Forward public ports on the relay server securely to any peer.
*   **🤖 Automated & Reliable**: Automatically generates a single, clean, and syntactically correct `nftables` ruleset, preventing conflicts and ensuring service stability.
*   **🎛️ Interactive TUI**: A simple, menu-driven interface means you don't have to memorize complex `nft` commands.
*   **🧹 Clean & Self-Contained**: Includes a built-in uninstaller to cleanly remove the script, all configurations, and firewall rules.

* * *

⚡ Quick Start: Run Without Installing
-------------------------------------

You can run Hyper-Route instantly without any permanent installation. This is perfect for quick tasks or trying it out.

Execute the following command on your server as root or with `sudo`:

    sudo bash -c "python3 <(curl -fsSL https://raw.githubusercontent.com/Nima786/Hyper-Route/main/tunnel-manager.py)"

This will download and run the script directly in memory.

* * *

💻 Local Installation (Recommended)
-----------------------------------

For regular use, it is highly recommended to install the script locally. This makes it available as a system-wide command.

1.  **Run the script once** using the Quick Start command above.
2.  From the main menu, choose option **3\. Install Script Locally**.
3.  The script will download itself to `/usr/local/bin/ultimate-tunnel-manager`, make it executable, and confirm the installation.

After installation, you can run it from anywhere on your system with a simple command:

    sudo ultimate-tunnel-manager

🕹️ How to Use
--------------

### Direct NAT Tunnel Management

Use this mode to forward ports from your server to another IP address (e.g., a machine on your local network).

1.  Run the script.
2.  Choose option **1\. Manage Direct NAT Tunnels**.
3.  Use the menu to **Add, List, Edit, or Remove** your tunnels. The script will automatically generate the required `nftables` rules.

### WireGuard Reverse Tunnel Management

This is a powerful mode for securely exposing services on a "Client Server" that might be behind a firewall or have a dynamic IP. The traffic is routed through a public "Relay Server."

#### Step 1: Initial Setup (On the Relay Server)

This only needs to be done once on your public-facing server.

1.  Run the script on your **Relay Server** (the one with the public IP).
2.  Choose option **2\. Manage Reverse WireGuard Tunnels**.
3.  Select **Initial Relay Setup**. This will install WireGuard and configure it as a central relay point.

#### Step 2: Add a Peer (Connecting a Client Server)

1.  On the **Relay Server**, go to the Reverse Tunnel Manager menu and select **1\. Add New Peer Server**.
2.  The script will generate a long one-line `curl | sudo python3 ...` command.
3.  **Copy this entire command**. Now, SSH into your **Client Server** (the one you want to connect _to_ the relay) and run the command there.
4.  The Client Server will automatically configure itself and securely register with your Relay Server.

#### Step 3: Create a Forwarding Rule

1.  Back on the **Relay Server**, go to the Reverse Tunnel Manager menu.
2.  Select **3\. Add New Forwarding Rule**.
3.  Choose which peer you want to forward traffic to and which public ports you want to use.

That's it! Traffic to the public port on your Relay Server will now be securely tunneled to the service running on your Client Server.

⚙️ Optional: Performance Tuning for Heavy Loads
-----------------------------------------------

For high-throughput servers, you can optimize the Linux kernel's network stack. Create a file named `/etc/sysctl.d/99-tunnel-optimizations.conf` and add the following settings:

    # Increase max socket buffer sizes
    net.core.rmem_max = 26214400
    net.core.wmem_max = 26214400
    
    # Increase TCP buffer sizes
    net.ipv4.tcp_rmem = 4096 87380 26214400
    net.ipv4.tcp_wmem = 4096 65536 26214400
    
    # Increase connection tracking table size for NAT
    net.netfilter.nf_conntrack_max = 1048576
    
    # Increase network device queue length
    net.core.netdev_max_backlog = 20000

Apply the settings by running `sudo sysctl --system`.

🗑️ Uninstalling Hyper-Route
----------------------------

Hyper-Route can be removed cleanly from your system.

1.  Run the script.
2.  From the main menu, choose option **4\. Uninstall Script and All Configs**.
3.  Confirm the action. The script will remove itself, all database files, the WireGuard configuration, and the `nftables` rules file, leaving your system clean.

📜 License
----------

This project is licensed under the MIT License. See the LICENSE file for details.
