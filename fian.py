#!/usr/bin/python3
import argparse
import ipaddress
import os
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import time

import qrcode
from scapy.all import IP, UDP, sniff


def run_command(cmd, capture_output=True, check=False, text=True, input_data=None, shell=False):
    """Run a system command and return the CompletedProcess object."""
    kwargs = {
        "capture_output": capture_output,
        "check": check,
        "text": text,
        "shell": shell,
    }
    if input_data:
        kwargs["input"] = input_data

    return subprocess.run(cmd, **kwargs)


def get_gateway_ip():
    """Return the default gateway IP from system routing."""
    result = run_command(['ip', 'route', 'show', 'default'])
    if result.returncode == 0:
        for line in result.stdout.splitlines():
            if line.startswith("default"):
                return line.split()[2]
    print(f"Error getting gateway IP: {result.stderr}")
    return None


def get_server_ip():
    """Return the server IP address used for outbound traffic."""
    try:
        result = run_command(['ip', 'route', 'get', '1.1.1.1'], check=True)
        match = re.search(r'src (\S+)', result.stdout)
        if match:
            return match.group(1)
        print("Could not find server IP from route output.")
    except Exception as e:
        print(f"Error getting server IP: {e}")
    return None


def generate_keypair():
    """Generate WireGuard private and public key pair."""
    priv_key = subprocess.check_output(['wg', 'genkey']).strip().decode()
    pub_key = subprocess.check_output(['wg', 'pubkey'], input=priv_key.encode()).strip().decode()
    return priv_key, pub_key


def write_file(path, content):
    """Write content to file safely."""
    try:
        with open(path, 'w') as f:
            f.write(content)
        print(f"Wrote file: {path}")
    except Exception as e:
        print(f"Failed to write {path}: {e}")
        raise


def generate_wireguard_config_and_systemd(cidr, name, table, fail_limit, wg_port):
    """
    Generate WireGuard server and client configs, and systemd service for the server.
    Writes server config to /etc/wireguard/wg-{name}.conf,
    client config to /etc/wireguard/{name}.conf,
    and systemd unit to /etc/systemd/system/fian@{name}.service
    """
    network = ipaddress.ip_network(cidr)
    interface_address = str(network.network_address + 1)  # e.g. 10.50.73.1
    client_address = str(network.network_address + 2)     # e.g. 10.50.73.2

    # Generate key pairs
    server_privkey, server_pubkey = generate_keypair()
    client_privkey, client_pubkey = generate_keypair()

    post_up_gateway = get_gateway_ip()
    server_ip = get_server_ip()

    if not server_ip:
        print("Failed to determine server IP; will fallback to client IP for Endpoint")
        server_ip = client_address

    post_up_ip = server_ip

    server_config = f"""[Interface]
PrivateKey = {server_privkey}
ListenPort = {wg_port}
Address = {interface_address}/24
PostUp = ip rule add from {post_up_ip} lookup {table}; ip rule add to {post_up_ip} lookup {table}; ip route add default via {post_up_gateway} table {table}
PostDown = ip rule delete from {post_up_ip} lookup {table}; ip rule delete to {post_up_ip} lookup {table}; ip route delete default via {post_up_gateway} table {table}

[Peer]
PublicKey = {client_pubkey}
AllowedIPs = {client_address}/32
"""

    client_config = f"""[Interface]
PrivateKey = {client_privkey}
Address = {client_address}/32
DNS = 1.1.1.1

[Peer]
PublicKey = {server_pubkey}
Endpoint = {server_ip}:{wg_port}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""

    server_path = f"/etc/wireguard/wg-{name}.conf"
    client_path = f"/etc/wireguard/{name}.conf"

    try:
        write_file(server_path, server_config)
        write_file(client_path, client_config)
    except Exception:
        return

    systemd_content = f"""[Unit]
Description=WireGuard via Fian for {name}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
RemainAfterExit=yes
ExecStart=/usr/bin/fian --wg-port {wg_port} --client-ip {client_address} --fail-limit {fail_limit} --config-path {server_path} --name {name} --forward
Restart=on-failure
RestartSec=5
User=root
Group=root
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
"""

    systemd_path = f"/etc/systemd/system/fian@{name}.service"
    try:
        write_file(systemd_path, systemd_content)
    except Exception:
        return

    try:
        print("\nClient WireGuard config QR code:\n")
        qr = qrcode.QRCode()
        qr.add_data(client_config)
        qr.make(fit=True)
        qr.print_ascii(invert=True)
        print(f"You're all set! Now just run: wg-quick up wg-{name} && systemctl daemon-reload && systemctl start fian@{name}")
    except Exception as e:
        print(f"Failed to generate QR code: {e}")


def capture_udp_packet(wireguard_port, timeout=3600):
    """Capture a single UDP packet on specified port within timeout."""
    print(f"Waiting for UDP packet on port {wireguard_port}...")
    packet_filter = f"udp dst port {wireguard_port}"
    packets = sniff(filter=packet_filter, count=1, timeout=timeout)

    if not packets:
        raise TimeoutError("No UDP packet captured within timeout")
        sleep(0.1)

    packet = packets[0]
    if not (packet.haslayer(IP) and packet.haslayer(UDP)):
        raise ValueError("Captured packet is not a valid UDP packet")

    source_ip = packet[IP].src
    source_port = packet[UDP].sport
    data = bytes(packet[UDP].payload)
    addr = (source_ip, source_port)

    return data, addr


def update_wireguard_template(source_ip, source_port, template_path, config_path, wireguard_port):
    """
    Update the Endpoint in the WireGuard config template and copy to config path.
    Adds an iptables rule to drop unwanted traffic.
    """
    try:
        with open(template_path, 'r') as f:
            config = f.read()

        new_endpoint = f"Endpoint = {source_ip}:{source_port}"

        match = re.search(r'Endpoint = ([^\n]+)', config)
        endpoint_changed = False

        if match:
            current_endpoint = match.group(0)
            if current_endpoint.strip() == new_endpoint:
                print(f"Endpoint already set to {new_endpoint}, skipping update.")
                return True
            else:
                config = re.sub(r'Endpoint = [^\n]*', new_endpoint, config)
                endpoint_changed = True
                try:
                    subprocess.run(
                        f"iptables -D INPUT $(iptables -L INPUT --line-numbers | grep {wireguard_port} | cut -d ' ' -f 1 | tac | xargs -I [] iptables -D INPUT []) || true",
                        check=True,
                        shell=True
                    )
                except subprocess.CalledProcessError as e:
                    print(f"Error adding iptables rule: {e}")
        else:
            if '[Peer]' in config:
                config = config.replace('[Peer]', f'[Peer]\n{new_endpoint}\n')
            else:
                config += f'\n[Peer]\n{new_endpoint}\n'
            endpoint_changed = True

        # Write updated config
        if os.path.abspath(template_path) == os.path.abspath(config_path):
            with open(config_path, 'w') as f:
                f.write(config)
            print(f"Overwrote {config_path} with updated content.")
        else:
            shutil.copy2(template_path, config_path)
            print(f"Copied {template_path} to {config_path}")

        print(f"Updated WireGuard template with Endpoint: {new_endpoint}")

        if endpoint_changed:
            try:
                subprocess.run(
                    f"iptables -C INPUT -p udp --dport {wireguard_port} ! --sport {source_port} ! -s {source_ip} -j DROP || iptables -I INPUT -p udp --dport {wireguard_port} ! --sport {source_port} ! -s {source_ip} -j DROP",
                    check=True,
                    shell=True
                )
            except subprocess.CalledProcessError as e:
                print(f"Error adding iptables rule: {e}")
            #try:
            #    print(f"Adding iptables rule: DROP everything to port {wireguard_port} except from {source_ip}:{source_port}")
            #    run_command([
            #        'iptables', '-I', 'INPUT',
            #        '-p', 'udp', '--dport', str(wireguard_port),
            #        '!', '-s', source_ip,
            #        '!', '--sport', str(source_port),
            #        '-j', 'DROP'
            #    ], check=True)
            #except subprocess.CalledProcessError as e:
            #    print(f"Error adding iptables INPUT rule: {e}")

        return True
    except Exception as e:
        print(f"Error updating WireGuard template or copying to config: {e}")
        return False



def sync_wireguard(name):
    try:
        print("Syncing WireGuard configuration...")
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
            subprocess.run(['wg-quick', 'strip', f'wg-{name}'], stdout=temp_file, check=True)
            temp_file_path = temp_file.name

        subprocess.run(['wg', 'syncconf', f'wg-{name}', temp_file_path], check=True)
        os.unlink(temp_file_path)
        print("WireGuard sync complete.")
    except subprocess.CalledProcessError as e:
        print(f"Error syncing WireGuard configuration: {e}")
        return False
    return True

def ping_peer(peer_ip):
    """Ping a peer IP address and return True if reachable."""
    try:
        print(f"Pinging peer at {peer_ip}...")
        result = run_command(['ping', '-c', '4', peer_ip])
        print(result.stdout)
        return result.returncode == 0
    except subprocess.CalledProcessError as e:
        print(f"Error pinging peer: {e}")
        return False


def forward_udp_packet(data, addr):
    """Forward UDP packet data to given address."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    time.sleep(0.3)  # slight delay
    sock.sendto(data, addr)
    print(f"Forwarded packet to {addr}")


def monitor_peer_connectivity(peer_ip, fail_limit, wireguard_port):
    failure_count = 0
    print(f"Starting peer connectivity monitor for {peer_ip}")

    while True:
        # Check if rule exists
        rule_exists = False
        try:
            subprocess.run(
                f"iptables -C OUTPUT -p udp --sport {wireguard_port} -j DROP",
                check=True,
                shell=True
            )
            rule_exists = True
        except subprocess.CalledProcessError:
            rule_exists = False

        if rule_exists:
            print(f"iptables DROP rule exists for port {wireguard_port}, skipping ping.")
            time.sleep(10)  # Sleep longer to avoid busy loop
            continue

        # Ping logic follows...
        try:
            result = run_command(['ping', '-c', '4', '-w', '5', peer_ip])
            if result.returncode == 0:
                failure_count = 0
                print(f"Ping to {peer_ip} succeeded.")
            else:
                failure_count += 1
                print(f"Ping to {peer_ip} failed ({failure_count}/{fail_limit}).")

            if failure_count >= fail_limit:
                print(f"{fail_limit} consecutive ping failures. Adding iptables DROP rule.")
                try:
                    subprocess.run(
                        f"iptables -I OUTPUT -p udp --sport {wireguard_port} -j DROP",
                        check=True,
                        shell=True
                    )
                    print(f"Added iptables DROP rule on UDP port {wireguard_port}.")
                except subprocess.CalledProcessError as e:
                    print(f"Error adding iptables DROP rule: {e}")
                try:
                    subprocess.run(
                        f"iptables -D INPUT $(iptables -L INPUT --line-numbers | grep {wireguard_port} | cut -d ' ' -f 1 | tac | xargs -I [] iptables -D INPUT []) || true",
                        check=True,
                        shell=True
                    )
                    print("iptables DROP rule added to INPUT chain.")
                except subprocess.CalledProcessError as e:
                    print(f"Error adding iptables rule: {e}")
                failure_count = 0
        except Exception as e:
            print(f"Exception in monitoring ping: {e}")

        time.sleep(5)


def main():
    parser = argparse.ArgumentParser(description="WireGuard tunnel manager")
    parser.add_argument('--wg-port', type=int, default=51820, help='WireGuard UDP port')
    parser.add_argument('--fail-limit', type=int, default=3, help='Ping fail limit before blocking port')
    parser.add_argument('--client-ip', type=str, help='Client IP address in WireGuard subnet')
    parser.add_argument('--config-path', type=str, help='Path to WireGuard config file')
    parser.add_argument('--name', type=str, default='wg0', help='Name for interface and systemd service')
    parser.add_argument('--cidr', type=str, default='10.50.73.0/24', help='CIDR for WireGuard network')
    parser.add_argument('--table', type=str, default='200', help='Routing table number to add rules for')
    parser.add_argument('--generate', action='store_true', help='Generate WireGuard configs and systemd service')
    parser.add_argument('--sync', action='store_true', help='Sync WireGuard config')
    parser.add_argument('--forward', action='store_true', help='Forward UDP packets from WireGuard port')

    args = parser.parse_args()

    if args.generate:
        generate_wireguard_config_and_systemd(args.cidr, args.name, args.table, args.fail_limit, args.wg_port)
        return

    if args.sync:
        sync_wireguard(args.name)
        return

    if args.forward:
        monitor_thread = threading.Thread(target=monitor_peer_connectivity, args=(args.client_ip, args.fail_limit, args.wg_port), daemon=True)
        monitor_thread.start()
        while True:

            if not args.config_path or not args.client_ip:
                print("Error: --config-path and --client-ip required for forwarding.")
                return

            try:

                data, addr = capture_udp_packet(args.wg_port)
                try:
                    subprocess.run(
                        f"iptables -C OUTPUT -p udp --sport {args.wg_port} -j DROP && iptables -D OUTPUT -p udp --sport {args.wg_port} -j DROP",
                        check=True,
                        shell=True
                    )
                except subprocess.CalledProcessError as e:
                    pass
    
                if update_wireguard_template(addr[0], addr[1], args.config_path, args.config_path, args.wg_port):
                    sync_wireguard(args.name)
                    forward_udp_packet(data, addr)


            except TimeoutError as te:
                print(te)
            except Exception as e:
                pass

    parser.print_help()
    return

if __name__ == "__main__":
    main()
