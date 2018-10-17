# VPN installer

This script will walk you through the installation of an OpenVPN server. It begins asking basic questions like the protocol, the port, DNS and the kind of encryption you want to use. Then it will automatically download necessary packages, configure the firewall and the server itself. If you are not sure about the settings, you can use the default ones, which are secure enough. Additionally, you can choose not to use the latest OpenVPN features (ECDSA, control channel encryption and LZ4 compressions) if you need compatibiliy with older clients. After the installation, you can use the same script to generate, list or revoke clients.

# Why?
By default, the server is set up to redirect all your internet traffic through the VPN tunnel. Therefore, you can use it to securely connect to machines inside your home network, browse the web when your smartphone is connected to a public wifi without risk of eavesdropping or bypass network restrictions (DNS filtering, IP blocking, ecc.).

# Compatibility
* Debian 7/8/9
* Ubuntu 14.04/16.04/18.04
* Raspbian 8/9 (some features are not available on Raspbian 8 because repos only have OpenVPN 2.3)

If your server is at home, it's probably behind a NAT, so you'll likely need to forward the port through your router. Also, if your ISP leases dynamic IPs you should sign up to a DDNS service to map a domain name to your public IP otherwhise you will continuously need to update the IP in your client config.

# Installation

```
wget https://raw.githubusercontent.com/orazioedoardo/vpn-installer/master/vpn.sh
chmod +x vpn.sh
sudo ./vpn.sh
```

### Available options:
* TCP/UDP protocol (default UDP)
* System/Google/OpenDNS/Quad9/Cloudflare/Custom DNS servers
* Connect via public IP or domain name
* No/LZO/LZ4 compression (default No, because of [possible attacks](https://www.mail-archive.com/openvpn-devel@lists.sourceforge.net/msg16919.html))
* RSA/ECDSA certificates (default ECDSA, curve prime256v1)
* AES-128-CBC, AES-192-CBC, AES-256-CBC encryption (default AES-128-CBC)
* SHA-256, SHA-384, SHA-512 digest (default SHA-256)
* Control channel authentication/\[encryption + authentication\] (default the latter)

![Installation](/png/1.png)

# Summary
![Installation](/png/2.png)

# Client creation
You can create as many clients as you want. They will be created in the home folder of the user you originally started the script from. The configuration should be transferred to the client using a preexisting secure channel like SSH, then you can connect to the server using OpenVPN, Tunnelblick or OpenVPN Connect depending on the client.

Watch out! If your certificate is stolen, anyone will be able to use it to connect to your network. Thus, it's recommended to protect the private key with a password (you can do it using the script) and revoke clients you don't need anymore. 

![Client creation](/png/3.png)

# Revoking clients
If you revoke a client you will be able to create a new client with the same name as the revoked one.

![Client revoking](/png/4.png)

# Listing clients
![Listing clients](/png/5.png)

Feel free to contribute or report bugs!
