#!/bin/bash

if [ $EUID -ne 0 ]; then
    echo "This script must be run as root"
    exit 1
fi

main() {
    clear
    echo "Welcome to the OpenVPN server installation script"
    if [ -f /etc/openvpn/server.conf ]; then
        echo "Looks like the server is already installed, then choose an option:"
        echo "1) Create a configuration file for a new client"
        echo "2) Show the available clients"
        echo "3) Revoke access to a client"
        echo "4) Uninstall the server"
        read -r -p "--> " CHOISE

        case "$CHOISE" in
            1)
            create_client
            ;;
            2)
            list_clients
            ;;
            3)
            revoke_client
            ;;
            4)
            uninstall_server
            ;;
            *)
            exit 1
        esac
    else
        install_server
    fi
}

install_server(){
    # This file will store some user provided settings for later referencing. We delete it first
    # to make sure there are no leftovers from aborted installations.
    rm -rf /etc/.install_settings

    # We use those variables to determine where to store .ovpn files and apply proper permissions.
    if [ -z "$SUDO_USER" ]; then
        HOME_DIR="$(getent passwd "$USER" | cut -d ':' -f 6)"
        CURRENT_USER="$USER"
    else
        HOME_DIR="$(getent passwd "$SUDO_USER" | cut -d ':' -f 6)"
        CURRENT_USER="$SUDO_USER"
    fi

    echo "HOME_DIR=\"$HOME_DIR\"" >> /etc/.install_settings
    echo "CURRENT_USER=\"$CURRENT_USER\"" >> /etc/.install_settings

    # Wget is required to get the public IP (the best way to do it would be to use dig but it's not
    # preinstalled on Ubuntu and Debian and we don't want to install a package even if the user
    # does not proceed with the installation).
    if ! hash wget 2> /dev/null; then
        echo "Wget program missing, please install it before proceeding"
        exit 1
    fi

    check_distro
    get_network
    choose_protocol
    input_port
    choose_dns
    choose_remote
    choose_compression
    choose_cert_type    
    choose_key_size
    choose_hash_size
    choose_tls_protection
    show_summary

    read -r -p "Proceed with the server installation? [Y/n] "
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        install_packages
        configure_firewall
        configure_logging
        create_pki
        create_server_template
        create_client_template
        
        echo -e "Installation has been completed, run the script again to create a configuration file for a client\n"
        read -r -p "It is recommended to reboot after installation, reboot now? [Y/n] "
        
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            reboot
        fi
    else
        exit 1
    fi
}

check_distro(){
    if [ ! -f /etc/os-release ]; then
        echo "Unable to detect the current system"
        exit 1
    fi
    source /etc/os-release

    COMPATIBLE="true"
    NEED_REPO="true"
    LEGACY="false"

    # Debian 9 and Ubuntu 18.04 already have OpenVPN 2.4 in their repositories so we don't need
    # to add the specific repository.
    if [ "$NAME" = "Debian GNU/Linux" ]; then

        if [ "$VERSION_ID" = "9" ]; then
            NEED_REPO="false"
        elif [ "$VERSION_ID" = "8" ]; then
            CODENAME="jessie"
        elif [ "$VERSION_ID" = "7" ]; then
            CODENAME="wheezy"
        else
            COMPATIBLE="false"
        fi

    elif [ "$NAME" = "Ubuntu" ]; then

        if [ "$VERSION_ID" = "18.04" ]; then
            NEED_REPO="false"
        elif [ "$VERSION_ID" = "16.04" ]; then
            CODENAME="xenial"
        elif [ "$VERSION_ID" = "14.04" ]; then
            CODENAME="trusty"
        else
            COMPATIBLE="false"
        fi

    elif [ "$NAME" = "Raspbian GNU/Linux" ]; then

        if [ "$VERSION_ID" = "9" ]; then
            NEED_REPO="false"
        elif [ "$VERSION_ID" = "8" ]; then
            NEED_REPO="false"

            # In legacy mode for Raspbian 8, ECDSA, LZ4 compression and tls-crypt can't be used.
            LEGACY="true"
        else
            COMPATIBLE="false"
        fi

    else
        COMPATIBLE="false"
    fi
    
    if [ "$COMPATIBLE" = "false" ]; then
        echo "This system is not supported"
        exit 1
    fi
}

get_network(){
    GW_IP="$(ip route get 8.8.8.8 | head -1 | awk '{print $3}')"
    IFACE="$(ip route get 8.8.8.8 | head -1 | awk '{print $5}')"
    IFACE_IP="$(ip route get 8.8.8.8 | head -1 | awk '{print $7}')"

    PUBLIC_IP="$(wget -qO- http://whatismyip.akamai.com)"
    if [ -z "$PUBLIC_IP" ]; then
        echo "Unable to detect the public IP address"
        exit 1
    fi

    echo "IFACE=\"$IFACE\"" >> /etc/.install_settings
}

choose_protocol(){
    local CHOISE=0
    local ARRAY=("tcp" "udp")

    until [ "$CHOISE" -eq 1 ] || [ "$CHOISE" -eq 2 ]; do
        echo "Choose the protocol you want to use:"
        echo "1) TCP"
        echo "2) UDP (default)"
        read -r -p "--> " CHOISE

        if [ -z "$CHOISE" ]; then
            PROTO="${ARRAY[1]}"
            CHOISE=1
        else
            PROTO="${ARRAY[(($CHOISE-1))]}"
        fi
    done
    
    echo "PROTO=\"$PROTO\"" >> /etc/.install_settings
}

input_port(){
    while true; do
        read -r -e -p "Input the port you want to use: " -i 1194 PORT
        if [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
            echo "Port must be between 1 and 65535"
        else
            break
        fi
    done
    
    echo "PORT=\"$PORT\"" >> /etc/.install_settings
}

# Function from https://stackoverflow.com/a/13777424
validate_ip(){
    local IP="$1" # Get the first argument passed to the function.
    local STAT=1 # Start with 1, so invalid.

    # Specify the format (numbers from 0 to 9 with 1 to 3 digits).
    if [[ "$IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then 
        OIFS=$IFS # Save the IFS.
        IFS='.' # Set a new IFS.
        IP=($IP) # Save the value as an array.
        IFS=$OIFS # Restore the IFS.
        [ "${IP[0]}" -le 255 ] && [ "${IP[1]}" -le 255 ] && [ "${IP[2]}" -le 255 ] && [ "${IP[3]}" -le 255 ] # Check whether the 4 octects are less or equal to 255.
        STAT=$? # Will be 0 on success.
    fi
    echo "$STAT"
}

choose_dns(){
    local CHOISE=0
    
    # Get system resolvers from /etc/resolv/conf. This should be improved to validate IP address and
    # also recognize 127.0.0.0/8 on systems that use dnsmasq for caching (like Ubuntu).
    local LOCAL_DNS=($(grep nameserver /etc/resolv.conf | awk '{print $2}'))
    local ARRAY=("$LOCAL_DNS" "8.8.8.8 8.8.4.4" "208.67.222.222 208.67.220.220" "9.9.9.9 149.112.112.112" "1.1.1.1 1.0.0.1")

    echo "Choose the DNS you want to use:"
    echo "1) Current ($LOCAL_DNS)"
    echo "2) Google"
    echo "3) OpenDNS"
    echo "4) Quad9"
    echo "5) Cloudflare"
    echo "6) Custom"

    until [ "$CHOISE" -ge 1 ] && [ "$CHOISE" -le 6 ]; do
        read -r -p "--> " CHOISE

        if [ -z "$CHOISE" ]; then
            echo "You haven't chosen any option"
            CHOISE=0
        else
            if [ "$CHOISE" -eq 6 ]; then
                local RET1=1
                local RET2=1

                while true; do
                    until [ -n "$DNS" ]; do
                        read -r -p "Input the DNS (max. 2) separated by a space: " DNS

                        if [ -z "$DNS" ]; then
                            echo "You haven't provided any DNS"
                        fi
                    done

                    local DNS1="$(awk '{print $1}' <<< "$DNS")"
                    local DNS2="$(awk '{print $2}' <<< "$DNS")"
                    RET1=$(validate_ip "$DNS1")

                    if [ -z "$DNS2" ]; then
                        RET2=0
                    else
                        RET2="$(validate_ip "$DNS2")"
                    fi

                    if [ "$RET1" -ne 0 ] || [ "$RET2" -ne 0 ]; then
                        echo "Invalid IP addresses"
                        DNS=""
                    else
                        break
                    fi
                done
            else
                DNS="${ARRAY[(($CHOISE-1))]}"
            fi
        fi
    done
}

choose_remote(){
    local CHOISE=0
    echo "Do you want to connect via a public IP or a domain name?"
    echo "1) IP address ($PUBLIC_IP)"
    echo "2) Domain name"

    until [ "$CHOISE" -eq 1 ] || [ "$CHOISE" -eq 2 ]; do
        read -r -p "--> " CHOISE

        if [ -z "$CHOISE" ]; then
            echo "You haven't chosen any option"
            CHOISE=0
        else
            if [ "$CHOISE" -eq 1 ]; then
                REMOTE="$PUBLIC_IP"
            else
                until [ -n "$REMOTE" ]; do
                    read -r -p "Provide the domain name you want to use: " REMOTE

                    if [ -z "$REMOTE" ]; then
                        echo "You haven't provided any domain"
                    fi
                done
            fi
        fi
    done
}

choose_compression(){
    local CHOISE=0
    local ARRAY=("none" "comp-lzo")

    if [ "$LEGACY" = "true" ]; then
        until [ "$CHOISE" -ge 1 ] && [ "$CHOISE" -le 2 ]; do
            echo "Choose the compression type you want to use:"
            echo "1) None (default)"
            echo "2) LZO"
            read -r -p "--> " CHOISE

            if [ -z "$CHOISE" ]; then
                COMP="${ARRAY[0]}"
                CHOISE=1
            else
                COMP="${ARRAY[(($CHOISE-1))]}"
            fi
        done
    else
        ARRAY+=("compress lz4")
        until [ "$CHOISE" -ge 1 ] && [ "$CHOISE" -le 3 ]; do
            echo "Choose the compression type you want to use:"
            echo "1) None (default)"
            echo "2) LZO (OpenVPN 2.3 compatible)"
            echo "3) LZ4"
            read -r -p "--> " CHOISE

            if [ -z "$CHOISE" ]; then
                COMP="${ARRAY[0]}"
                CHOISE=1
            else
                COMP="${ARRAY[(($CHOISE-1))]}"
            fi
        done
    fi
}

choose_cert_type(){
    if [ "$LEGACY" = "true" ]; then
        choose_rsa_size
        CERT="RSA"
    else
        local CHOISE=0

        until [ "$CHOISE" -eq 1 ] || [ "$CHOISE" -eq 2 ]; do
            echo "Do you want to generate RSA or ECDSA certificates?"
            echo "1) RSA (OpenVPN 2.3 compatible)"
            echo "2) ECDSA (default)"
            read -r -p "--> " CHOISE

            if [ -z "$CHOISE" ] || [ "$CHOISE" -eq 2 ]; then
                choose_ecdsa_size
                CERT="ECDSA"
                CHOISE=1
            elif [ "$CHOISE" -eq 1 ]; then
                choose_rsa_size
                CERT="RSA"
            fi
        done
    fi
}

choose_rsa_size(){
    local CHOISE=0
    local ARRAY=("2048" "3072" "4096")

    until [ "$CHOISE" -ge 1 ] && [ "$CHOISE" -le 3 ]; do
        echo "Choose the certificate size:"
        echo "1) 2048 bit (default)"
        echo "2) 3072 bit"
        echo "3) 4096 bit"
        read -r -p "--> " CHOISE

        if [ -z "$CHOISE" ]; then
            RSA="${ARRAY[0]}"
            CHOISE=1
        else
            RSA="${ARRAY[(($CHOISE-1))]}"
        fi
    done
}

choose_ecdsa_size(){
    local CHOISE=0
    local ARRAY=("prime256v1" "secp384r1" "secp521r1")

    until [ "$CHOISE" -ge 1 ] && [ "$CHOISE" -le 3 ]; do
        echo "Choose the certificate size:"
        echo "1) 256 bit (default)"
        echo "2) 384 bit"
        echo "3) 521 bit"
        read -r -p "--> " CHOISE

        if [ -z "$CHOISE" ]; then
            ECDSA="${ARRAY[0]}"
            CHOISE=1
        else
            ECDSA="${ARRAY[(($CHOISE-1))]}"
        fi
    done
}

choose_key_size(){
    local CHOISE=0
    
    # Actually GCM mode is more secure but it requires OpenVPN 2.4, so we should use a prompt for
    # legacy servers and another for new servers. However, specifying CBC only (instead of both),
    # makes a smaller function and 2.4 clients will be upgraded to GCM mode anyways because of their
    # "negotiable crypto parameters" feature.
    local ARRAY=("AES-128-CBC" "AES-192-CBC" "AES-256-CBC")

    until [ "$CHOISE" -ge 1 ] && [ "$CHOISE" -le 3 ]; do
        echo "Choose the key size:"
        echo "1) 128 bit (default)"
        echo "2) 192 bit"
        echo "3) 256 bit"
        read -r -p "--> " CHOISE

        if [ -z "$CHOISE" ]; then
            KEY="${ARRAY[0]}"
            CHOISE=1
        else
            KEY="${ARRAY[(($CHOISE-1))]}"
        fi
    done
}

choose_hash_size(){
    local CHOISE=0
    local ARRAY=("SHA256" "SHA384" "SHA512")

    until [ "$CHOISE" -ge 1 ] && [ "$CHOISE" -le 3 ]; do
        echo "Choose the hash size:"
        echo "1) 256 bit (default)"
        echo "2) 384 bit"
        echo "3) 512 bit"
        read -r -p "--> " CHOISE

        if [ -z "$CHOISE" ]; then
            HASH="${ARRAY[0]}"
            CHOISE=1
        else
            HASH="${ARRAY[(($CHOISE-1))]}"
        fi
    done
}

choose_tls_protection(){
    if [ "$LEGACY" = "true" ]; then
        TLS_PROT="tls-auth"
    else
        local CHOISE=0
        local ARRAY=("tls-crypt" "tls-auth")

        until [ "$CHOISE" -eq 1 ] || [ "$CHOISE" -eq 2 ]; do
            echo "Choose the control channel protection type:"
            echo "1) Encrypt and authenticate (default)"
            echo "2) Authenticate (OpenVPN 2.3 compatible)"
            read -r -p "--> " CHOISE

            if [ -z "$CHOISE" ]; then
                TLS_PROT="${ARRAY[0]}"
                CHOISE=1
            else
                TLS_PROT="${ARRAY[(($CHOISE-1))]}"
            fi
        done
    fi
    
    echo "TLS_PROT=\"$TLS_PROT\"" >> /etc/.install_settings
}

show_summary(){
    echo "Settings summary:"
    echo "- Network interface $IFACE"
    
    if [ "$REMOTE" = "$PUBLIC_IP" ]; then
        echo "- IP address $PUBLIC_IP"
    else
        echo "- Domain name $REMOTE"
    fi
    
    echo "- Protocol $(awk '{print toupper($0)}' <<< "$PROTO")"
    echo "- Port $PORT"
    echo "- DNS server $DNS"
    
    if [ "$CERT" = "RSA" ]; then
        echo "- RSA certificate $RSA bit"
    elif [ "$CERT" = "ECDSA" ]; then
        echo "- ECDSA certificate $ECDSA"
    fi
    
    echo "- Symmetric key $KEY"
    echo "- Hash function $HASH"

    if [ "$COMP" != "none" ]; then
        if [ "$COMP" = "comp-lzo" ]; then
            echo "- LZO commpresssion"
        elif [ "$COMP" = "compress lz4" ]; then
            echo "- LZ4 compression"
        fi
    fi

    if [ "$TLS_PROT" = "tls-crypt" ]; then
        echo "- Control channel encryption and authentication ($TLS_PROT)"
    elif [ "$TLS_PROT" = "tls-auth" ]; then
        echo "- Control channel authentication ($TLS_PROT)"
    fi

    if [ "$IFACE_IP" != "$PUBLIC_IP" ]; then
        echo -e "\nNOTE: since this server seems to be behind a NAT, to allow clients to initiate connections with the server you will need to forward, via the gateway $GW_IP, port $PORT to the local IP $IFACE_IP\n"
    fi
}

is_installed(){
    dpkg-query -W -f='${Status}' "$1" 2> /dev/null | grep -q 'install ok installed' && return 0 || return 1
}

install_packages(){
    USE_UFW="false"
    local TO_INSTALL=()

    if [ "$NEED_REPO" = "true" ]; then
        wget -O- https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
        echo "deb http://build.openvpn.net/debian/openvpn/stable $CODENAME main" > /etc/apt/sources.list.d/openvpn.list
    fi

    # Ufw will be used only if it is installed and active, since sometimes is preinstalled but not
    # actually used.
    if is_installed "ufw" && LANG="en_US.UTF-8" ufw status | grep -qw active; then
        USE_UFW="true"
    fi

    # We set these options non-interactively to prevent the user from being prompted.
    if ! is_installed "iptables-persistent" && [ "$USE_UFW" = "false" ]; then
        debconf-set-selections <<< "iptables-persistent iptables-persistent/autosave_v4 boolean false"
        debconf-set-selections <<< "iptables-persistent iptables-persistent/autosave_v6 boolean false"
        TO_INSTALL+=("iptables-persistent")
    fi

    # If openvpn is installed but we have added the repo we mark the package for installation so it
    # will be upgraded.
    if ! is_installed "openvpn" || [ "$NEED_REPO" = "true" ]; then
        TO_INSTALL+=("openvpn")
    fi

    # Expect is used to interact with easy-rsa.
    if ! is_installed "expect"; then
        TO_INSTALL+=("expect")
    fi

    apt-get update
    apt-get install -y --no-install-recommends "${TO_INSTALL[@]}"
    
    echo "USE_UFW=\"$USE_UFW\"" >> /etc/.install_settings
    echo "TO_INSTALL=\"${TO_INSTALL[*]}\"" >> /etc/.install_settings
}

configure_firewall(){
    # We save the state of IP forwarding for later restoring in case it's already enabled.
    local IP_FORWARD_STATUS="$(cat /proc/sys/net/ipv4/ip_forward)"

    if [ "$IP_FORWARD_STATUS" -eq 0 ]; then
        sed "/net.ipv4.ip_forward=1/s/^#//g" -i /etc/sysctl.conf
        sysctl -p
    fi

    local INPUT_CHAIN_EDITED="false"
    local FORWARD_CHAIN_EDITED="false"

    if [ "$USE_UFW" = "true" ]; then
        
        # If ufw is active, by default it has policy DROP both on INPUT as well as FORWARD,
        # so we need to allow connections to the port and explicitly forward packets.
        ufw insert 1 allow "$PORT"/"$PROTO"
        ufw route insert 1 allow in on tun0 from 10.8.0.0/24 out on "$IFACE" to any
        
        # There is no front-end commmand to perform masquerading, so we need to edit the rules file.
        sed "/delete these required/i *nat\n:POSTROUTING ACCEPT [0:0]\n-I POSTROUTING -s 10.8.0.0/24 -o $IFACE -j MASQUERADE\nCOMMIT\n" -i /etc/ufw/before.rules
        ufw reload
    else
        # Now some checks to detect which rules we need to add. On a newly installed system all policies
        # should be ACCEPT, so the only required rule would be the MASQUERADE one.
        
        # Count how many rules are in the INPUT and FORWARD chain. When parsing input from
        # iptables -S, '^-P' skips the policies and 'ufw-' skips ufw chains (in case ufw was found
        # installed but not enabled).
        local INPUT_RULES_COUNT="$(iptables -S INPUT | grep -vcE '(^-P|ufw-)')"
        local FORWARD_RULES_COUNT="$(iptables -S FORWARD | grep -vcE '(^-P|ufw-)')"

        local INPUT_POLICY="$(iptables -S INPUT | grep '^-P' | awk '{print $3}')"
        local FORWARD_POLICY="$(iptables -S FORWARD | grep '^-P' | awk '{print $3}')"

        # If rules count is not zero, we assume we need to explicitly allow traffic. Same conclusion if
        # there are no rules and the policy is not ACCEPT. Note that rules are being added to the top of the
        # chain (using -I).
        if [ "$INPUT_RULES_COUNT" -ne 0 ] || [ "$INPUT_POLICY" != "ACCEPT" ]; then
            iptables -I INPUT 1 -i "$IFACE" -p "$PROTO" -m "$PROTO" --dport "$PORT" -j ACCEPT
            INPUT_CHAIN_EDITED="true"
        fi

        if [ "$FORWARD_RULES_COUNT" -ne 0 ] || [ "$FORWARD_POLICY" != "ACCEPT" ]; then
            iptables -I FORWARD 1 -d 10.8.0.0/24 -i "$IFACE" -o tun0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
            iptables -I FORWARD 2 -s 10.8.0.0/24 -i tun0 -o "$IFACE" -j ACCEPT
            FORWARD_CHAIN_EDITED="true"
        fi

        iptables -t nat -I POSTROUTING 1 -s 10.8.0.0/24 -o "$IFACE" -j MASQUERADE
        iptables-save > /etc/iptables/rules.v4
    fi

    echo "INPUT_CHAIN_EDITED=\"$INPUT_CHAIN_EDITED\"" >> /etc/.install_settings
    echo "FORWARD_CHAIN_EDITED=\"$FORWARD_CHAIN_EDITED\"" >> /etc/.install_settings
    echo "IP_FORWARD_STATUS=\"$IP_FORWARD_STATUS\"" >> /etc/.install_settings
}

configure_logging(){

    # I just copied another daemon config here.
    echo "if \$programname == 'ovpn-server' then /var/log/openvpn.log
if \$programname == 'ovpn-server' then ~" > /etc/rsyslog.d/30-openvpn.conf

    echo "/var/log/openvpn.log
{
    rotate 4m
    weekly
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        invoke-rc.d rsyslog rotate >/dev/null 2>&1 || true
    endscript
}" > /etc/logrotate.d/openvpn
    service rsyslog restart
}

create_pki(){
    cd /etc/openvpn
    wget https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.4/EasyRSA-3.0.4.tgz
    tar xzf EasyRSA-3.0.4.tgz
    mv EasyRSA-3.0.4 easy-rsa
    rm -rf EasyRSA-3.0.4.tgz
    chown root:root easy-rsa

    cd easy-rsa
    echo "set_var EASYRSA /etc/openvpn/easy-rsa" >> vars
    echo "set_var EASYRSA_PKI /etc/openvpn/easy-rsa/pki" >> vars
    if [ "$CERT" = "RSA" ]; then
        echo "set_var EASYRSA_ALGO rsa" >> vars
        echo "set_var EASYRSA_KEY_SIZE $RSA" >> vars
    elif [ "$CERT" = "ECDSA" ]; then
        echo "set_var EASYRSA_ALGO ec" >> vars
        echo "set_var EASYRSA_CURVE $ECDSA" >> vars
    fi
    echo "set_var EASYRSA_DIGEST $(awk '{print tolower($0)}' <<< "$HASH")" >> vars
    echo "set_var EASYRSA_CRL_DAYS 3650" >> vars

    SERVER_NAME="server_$(tr -dc 'a-zA-Z0-9' < /dev/urandom | fold -w 16 | head -1)"
    
    if ! ./easyrsa --batch init-pki; then
        echo "An error has occured while initializing the PKI"
        exit 1
    fi

    if ! ./easyrsa --batch build-ca nopass; then
        echo "An error has occured while creating the CA"
        exit 1
    fi
    
    if ! ./easyrsa build-server-full "$SERVER_NAME" nopass; then
        echo "An error has occured while creating the server certificates"
        exit 1
    fi
    
    if ! ./easyrsa gen-crl; then
        echo "An error has occured while generating the CRL"
        exit 1
    fi
    
    cp pki/crl.pem /etc/openvpn/crl.pem
    chown nobody:nogroup /etc/openvpn/crl.pem

    if [ "$CERT" = "RSA" ]; then
        if ! ./easyrsa gen-dh; then
            echo "An error has occured while generating the DH parameters"
            exit 1
        fi
    fi

    if ! openvpn --genkey --secret pki/ta.key; then
        echo "An error has occured while generating the static key"
        exit 1
    fi
}

create_server_template(){
    cd /etc/openvpn
    echo "dev tun
proto $PROTO
port $PORT
ca /etc/openvpn/easy-rsa/pki/ca.crt
cert /etc/openvpn/easy-rsa/pki/issued/$SERVER_NAME.crt
key /etc/openvpn/easy-rsa/pki/private/$SERVER_NAME.key
topology subnet
server 10.8.0.0 255.255.255.0
push \"redirect-gateway def1\"
client-to-client
keepalive 10 120
remote-cert-tls client
tls-version-min 1.2
cipher $KEY
auth $HASH
user nobody
group nogroup
persist-key
persist-tun
crl-verify /etc/openvpn/crl.pem
status /var/log/openvpn-status.log 20
status-version 3
syslog
verb 3" >> server.conf

    if [ "$CERT" = "RSA" ]; then
        echo "dh /etc/openvpn/easy-rsa/pki/dh.pem" >> server.conf
    elif [ "$CERT" = "ECDSA" ]; then
        echo "dh none" >> server.conf
    fi

    if [ "$TLS_PROT" = "tls-crypt" ]; then
        echo "tls-crypt /etc/openvpn/easy-rsa/pki/ta.key" >> server.conf
    elif [ "$TLS_PROT" = "tls-auth" ]; then
        echo "tls-auth /etc/openvpn/easy-rsa/pki/ta.key 0" >> server.conf
    fi

    if [ "$COMP" != "none" ]; then
        echo "$COMP" >> server.conf
    fi

    local DNS1="$(awk '{print $1}' <<< "$DNS")"
    local DNS2="$(awk '{print $2}' <<< "$DNS")"
    echo "push \"dhcp-option DNS $DNS1\"" >> server.conf
    if [ -n "$DNS2" ]; then
        echo "push \"dhcp-option DNS $DNS2\"" >> server.conf
    fi
    
    service openvpn restart
}

create_client_template(){
    cd /etc/openvpn/easy-rsa/pki
    echo "client
dev tun
proto udp
remote $REMOTE $PORT
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
tls-version-min 1.2
verify-x509-name $SERVER_NAME name
cipher $KEY
auth $HASH
verb 3" >> template.txt

    if [ "$COMP" != "none" ]; then
        echo "$COMP" >> template.txt
    fi

    if [ "$TLS_PROT" = "tls-auth" ]; then
        echo "key-direction 1" >> template.txt
    fi
}

list_clients(){
    cd /etc/openvpn/easy-rsa/pki
    if [ ! -f dates.txt ]; then
        echo "You haven’t created any client yet"
        exit 1
    fi

    # Present the user with a summary of the clients, fetching info from dates.txt.
    local FORMATTED+="Client&Status&Creation date&Revocation date\n"

    while read -r LINE; do
        local CLIENT_NAME="$(awk '{print $1}' <<< "$LINE")"

        local CREATION_DATE="$(awk '{print $2}' <<< "$LINE")"
        
        # Dates are converted from UNIX time to human readable.
        local CD_FORMAT="$(date -d @"$CREATION_DATE" +'%d %b %Y, %H:%M, %Z')"

        local REVOCATION_DATE="$(awk '{print $3}' <<< "$LINE")"
        if [ -n "$REVOCATION_DATE" ]; then
            local RD_FORMAT="$(date -d @"$REVOCATION_DATE" +'%d %b %Y, %H:%M, %Z')"
            local STATUS="Revoked"
        else
            local RD_FORMAT="---"
            local STATUS="Valid"
        fi

        FORMATTED+="$CLIENT_NAME&$STATUS&$CD_FORMAT&$RD_FORMAT\n"
    done < dates.txt

    echo -e "$FORMATTED" | column -t -s '&'
}

create_client(){
    if [ ! -f /etc/.install_settings ]; then
        echo "Missing server settings"
        exit 1
    fi
    source /etc/.install_settings

    # The home folder variable was sourced from the settings file.
    if [ ! -d "$HOME_DIR/ovpns" ]; then
        mkdir "$HOME_DIR/ovpns"
        chown "$CURRENT_USER":"$CURRENT_USER" "$HOME_DIR/ovpns"
    fi

    cd /etc/openvpn/easy-rsa
    if [ ! -d pki/ovpns ]; then
        mkdir pki/ovpns
    fi

    while true; do
        while true; do
            read -r -p "Input a name for the client: " CLIENT_NAME
            if [ -z "$CLIENT_NAME" ]; then
                echo "You haven't provided any name"
            else

                # Enforcing alphanumeric characters makes easy to parse names later.
                if [[ "$CLIENT_NAME" =~ [^a-zA-Z0-9] ]]; then
                    echo "You can only use alphanumeric characters"
                else
                    break
                fi
            fi
        done
        if [ -f "pki/ovpns/$CLIENT_NAME.ovpn" ]; then
            echo "A client with this name already exists"
        else
            break
        fi
    done
    
    while true; do
        read -r -s -p "Input a password for the client (press enter not to use it): " PASSWD1
        echo

        if [ ${#PASSWD1} -ge 4 ] && [ ${#PASSWD1} -le 1024 ] || [ ${#PASSWD1} -eq 0 ]; then
            if [ -z "$PASSWD1" ]; then
                USE_PASS="false"
                break
            else
                USE_PASS="true"
                read -r -s -p "Re-enter the password to confirm: " PASSWD2
                echo
                if [ "$PASSWD1" != "$PASSWD2" ]; then
                    echo "Passwords do not match"
                else
                    break
                fi
            fi
        else
            echo "Password must be between 4 and 1024 characters"
        fi
    done
    
    # Non alphanumeric characters must be escaped otherwhise expect will complain.
    PASSWD1="$(echo -n "$PASSWD1" | sed 's/[^a-zA-Z0-9]/\\&/g')"

    if [ "$USE_PASS" = "true" ]; then
        expect << EOF
        set timeout -1
        spawn ./easyrsa build-client-full "$CLIENT_NAME"

        # A 0.1 seconds delay prevents the password from showing on the screen. The two dashes
        # keep expect from parsing passwords starting with '-' as commands.
        expect "Enter PEM pass phrase:" { sleep 0.1; send -- "$PASSWD1\r" }
        expect "Verifying - Enter PEM pass phrase:" { sleep 0.1; send -- "$PASSWD1\r" }
        expect eof
EOF
        if [ $? -ne 0 ]; then
            echo "An error has occured during the creation of the client configuration"
            exit 1
        fi
    else
        if ! ./easyrsa build-client-full "$CLIENT_NAME" nopass; then
            echo "An error has occured during the creation of the client configuration"
            exit 1
        fi
    fi
    
    cd pki
    {
    cat template.txt
 
    echo "<ca>"
    cat ca.crt
    echo "</ca>"

    echo "<cert>"
    openssl x509 < "issued/$CLIENT_NAME.crt"
    echo "</cert>"

    echo "<key>"
    cat "private/$CLIENT_NAME.key"
    echo "</key>"

    echo "<$TLS_PROT>"
    cat ta.key
    echo "</$TLS_PROT>"
    } >> "ovpns/$CLIENT_NAME.ovpn"

    cp "ovpns/$CLIENT_NAME.ovpn" "$HOME_DIR/ovpns/$CLIENT_NAME.ovpn"
    chown "$CURRENT_USER":"$CURRENT_USER" "$HOME_DIR/ovpns/$CLIENT_NAME.ovpn"

    echo "$CLIENT_NAME $(date +%s)" >> dates.txt
        
    echo -e "\nConfiguration file for $CLIENT_NAME saved at $HOME_DIR/ovpns/$CLIENT_NAME.ovpn"
}

revoke_client(){
    if [ ! -f /etc/.install_settings ]; then
        echo "Missing server settings"
        exit 1
    fi
    source /etc/.install_settings

    cd /etc/openvpn/easy-rsa
    local VALID=($(grep '^V' pki/index.txt | awk -F '/CN=' '{print $2}' | tail +2))

    if [ ${#VALID[@]} -eq 0 ]; then
        echo "There are no clients to revoke"
        exit 1
    fi

    local COUNTER=1
    echo "Choose which client you want to revoke:"
    while [ $COUNTER -le ${#VALID[@]} ]; do
        echo "$COUNTER) ${VALID[(($COUNTER-1))]}"
        ((COUNTER++))
    done

    local CHOISE=0
    while true; do
        read -r -p "--> " CHOISE

        if [ -z "$CHOISE" ]; then
            echo "You haven't chosen any client"
            CHOISE=0
        else
            if [ "$CHOISE" -lt 1 ] || [ "$CHOISE" -gt ${#VALID[@]} ]; then
                echo "Invalid choise"
            else
                local CLIENT_NAME="${VALID[(($CHOISE-1))]}"
                
                # This checksum will be used later inside this function.
                REQUESTED="$(sha256sum "pki/ovpns/$CLIENT_NAME.ovpn" | cut -c 1-64)"
                read -r -p "Do you really want to revoke $CLIENT_NAME? [Y/n] "

                if [[ $REPLY =~ ^[Yy]$ ]]; then
                    if ! ./easyrsa --batch revoke "$CLIENT_NAME"; then
                        echo "An error has occured while revoking the access"
                        exit 1
                    fi

                    if ! ./easyrsa gen-crl; then
                        echo "An error has occured while generating the CRL"
                        exit 1
                    fi

                    cd pki
                    rm -rf "reqs/$CLIENT_NAME.req"
                    rm -rf "private/$CLIENT_NAME.key"
                    rm -rf "issued/$CLIENT_NAME.crt"
                    rm -rf "ovpns/$CLIENT_NAME.ovpn"
                    cp crl.pem "/etc/openvpn/crl.pem"

                    # Find all .ovpn files in the home folder of the user matching the checksum of the
                    # revoked config and delete them. '-maxdepth 3' is used to avoid traversing too
                    # many folders.
                    find "$HOME_DIR" -maxdepth 3 -type f -name '*.ovpn' -print0 | while IFS= read -r -d '' CONFIG; do
                        if sha256sum -c <<< "$REQUESTED  $CONFIG" &> /dev/null; then
                            rm -rf "$CONFIG"
                        fi
                    done

                    # Save the revocation date in UNIX time.
                    CREATION_DATE="$(grep "$CLIENT_NAME" dates.txt | awk '{print $2}')"
                    REVOCATION_DATE="$(date +%s)"
                    sed "s/$CLIENT_NAME $CREATION_DATE/& $REVOCATION_DATE/" -i dates.txt

                    echo "Successfully revoked access"
                    break
                else
                    exit 1
                fi
            fi
        fi
    done
}

uninstall_server(){
    if [ ! -f /etc/.install_settings ]; then
        echo "Missing server settings"
        exit 1
    fi
    source /etc/.install_settings

    read -r -p "Proceed with the server uninstallation? [Y/n] "
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        service openvpn stop

        cd /etc/openvpn/easy-rsa/pki
        local VALID=($(grep '^V' index.txt | awk -F '/CN=' '{print $2}' | tail +2))

        # Find and delete all valid client configs in the home folder of the user.
        for CLIENT_NAME in "${VALID[@]}"; do
            REQUESTED="$(sha256sum "ovpns/$CLIENT_NAME.ovpn" | cut -c 1-64)"
            find "$HOME_DIR" -maxdepth 3 -type f -name '*.ovpn' -print0 | while IFS= read -r -d '' CONFIG; do
                if sha256sum -c <<< "$REQUESTED  $CONFIG" &> /dev/null; then
                    rm -rf "$CONFIG"
                fi
            done
        done

        rm -rf /etc/openvpn/server.conf
        rm -rf /etc/openvpn/crl.pem
        rm -rf /etc/openvpn/easy-rsa

        rm -rf /var/log/openvpn.log
        rm -rf /var/log/openvpn.log.*
        rm -rf /var/log/openvpn-status.log
        rm -rf /etc/logrotate.d/openvpn
        rm -rf /etc/rsyslog.d/30-openvpn.conf

        if [ "$IP_FORWARD_STATUS" -eq 0 ]; then
            sed "/net.ipv4.ip_forward=1/s/^/#/g" -i /etc/sysctl.conf
            sysctl -p
        fi

        # Removing firewall rules.
        if [ "$USE_UFW" = "true" ]; then
            ufw delete allow "$PORT"/"$PROTO"
            ufw route delete allow in on tun0 from 10.8.0.0/24 out on "$IFACE" to any
            sed -z "s/*nat\n:POSTROUTING ACCEPT \[0:0\]\n-I POSTROUTING -s 10.8.0.0\/24 -o $IFACE -j MASQUERADE\nCOMMIT\n\n//" -i /etc/ufw/before.rules
            ufw reload
        elif [ "$USE_UFW" = "false" ]; then
            if [ "$INPUT_CHAIN_EDITED" = "true" ]; then
                iptables -D INPUT -i "$IFACE" -p "$PROTO" -m "$PROTO" --dport "$PORT" -j ACCEPT
            fi

            if [ "$FORWARD_CHAIN_EDITED" = "true" ]; then
                iptables -D FORWARD -d 10.8.0.0/24 -i "$IFACE" -o tun0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
                iptables -D FORWARD -s 10.8.0.0/24 -i tun0 -o "$IFACE" -j ACCEPT
            fi

            iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o "$IFACE" -j MASQUERADE
            iptables-save > /etc/iptables/rules.v4
        fi

        # During installation we saved the list of newly installed packages, now we prompt the user
        # to uninstall them. For example, if openvpn was already installed before running the script,
        # the user won't be prompted to uninstall it.
        local INSTALLED=(${TO_INSTALL[@]})

        if [ ${#INSTALLED[@]} -ne 0 ]; then
            echo -e "\nThe server has been uninstalled, however the are still some packages that had been installed alongside the server.\nNow you will be asked to remove them one by one, choose no if you think you may need them or you are not sure.\n"

            local TO_UNINSTALL=()
            for PACKAGE in "${INSTALLED[@]}"; do
                read -r -p "Uninstall $PACKAGE? [y/N] "
                if [[ $REPLY =~ ^[Yy]$ ]]; then
                    TO_UNINSTALL+=("$PACKAGE")
                fi
            done

            if [ ${#TO_UNINSTALL[@]} -ne 0 ]; then
                apt-get -y remove --purge "${TO_UNINSTALL[@]}"
                apt-get -y autoremove
            fi
            echo
        else
            echo -e "\nThe server has been uninstalled\n"
        fi

        rm -rf /etc/.install_settings

        read -r -p "It is recommended to reboot after uninstallation, reboot now? [Y/n] "
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            reboot
        fi
    else
        exit 1
    fi
}

main "$@"
