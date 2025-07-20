# Fian
Fian is a simple script for setting up Wireguard Reverse VPN.

# Why it works

If you setup a Wireguard server on for example a Germany VPS, chances are your setup will never work. Handshakes sent from Iran to Germany will never each client because the censorship will flag source IP + Port and destination IP + Port, and block handshake answer from Germany to Iran.

But Fian does a simple trick, it reverses the process.

It will extract source IP and Port of first handshake sent from client, and will drop handshake answer of Wireguard server to client (Germany to Iran). After that, a completely new handshake will be sent from Wireguard server (Germany) to the client (Iran). This works because the nat hole is punched already and we've learned the source IP + Port of client.

And that's it! You have a working VPN without having to setup a bridge in Iran. The connection is mostly stable and I've had no issues so far.


# How it works
Fian is just a script which sniffs UDP packets on the same port Wireguard is listening (for example, 22744). It patiently waits for the first handshake sent by client.

To drop first handshale, it adds an iptable rule to drop outgoing packets from Wireguard port. When a handshake is received from client, the answer will be blocked by iptable rule. After that, the rule will be removed.

Once we made sure no handshakes are being processed from Iran to Wireguard server, Fian will extract source IP and source port of client, replace it in **Endpoint** section of Wireguard config for that client (This is why each client must be unique port-wise). After updating Endpoint, it will reload wireguard, and starts pinging client private IP. This forces a handshake being sent from Wireguard server to client, and the censorship somehow gets bypassed.


## Usage

To create a client, use:
```bash
fian --gen --cidr=10.50.82.0/24 --name=saber --table=103 --wg-port 22744 --fail-limit 3
```

It will generate Wireguard config for server side and systemd service for Fian. It also creates a config for client, which will be shown as QR code and can be imported.

After generating the necessary configs, Fian will tell you to start Wireguard and Fian services:

```bash
wg-quick up wg-saber && systemctl daemon-reload && systemctl start fian@saber
```


### WARNING

All arguments passed to fian MUST be unique (except for fail limit). Unique arguments are: CIDR, name, table, and Wireguard port.

