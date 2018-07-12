#!/bin/sh

result=0
mtd_part_name="Storage"
mtd_part_dev="/dev/mtdblock5"
mtd_part_size=65536
dir_storage="/etc/storage"
slk="/tmp/.storage_locked"
tmp="/tmp/storage.tar"
tbz="${tmp}.bz2"
hsh="/tmp/hashes/storage_md5"

EOF_STR="EOF"

func_get_mtd()
{
	local mtd_part mtd_char mtd_idx mtd_hex
	mtd_part=`cat /proc/mtd | grep \"$mtd_part_name\"`
	mtd_char=`echo $mtd_part | cut -d':' -f1`
	mtd_hex=`echo $mtd_part | cut -d' ' -f2`
	mtd_idx=`echo $mtd_char | cut -c4-5`
	if [ -n "$mtd_idx" ] && [ $mtd_idx -ge 4 ] ; then
		mtd_part_dev="/dev/mtdblock${mtd_idx}"
		mtd_part_size=`echo $((0x$mtd_hex))`
		echo $mtd_part_size > /tmp/.storage_size
	else
		logger -t "Storage" "Cannot find MTD partition: $mtd_part_name"
		exit 1
	fi
}

func_mdir()
{
	[ ! -d "$dir_storage" ] && mkdir -p -m 755 $dir_storage
}

func_stop_apps()
{
	killall -q rstats
	[ $? -eq 0 ] && sleep 1
}

func_start_apps()
{
	/sbin/rstats
}

func_load()
{
	local fsz

	bzcat $mtd_part_dev > $tmp 2>/dev/null
	fsz=`stat -c %s $tmp 2>/dev/null`
	if [ -n "$fsz" ] && [ $fsz -gt 0 ] ; then
		md5sum $tmp > $hsh
		tar xf $tmp -C $dir_storage 2>/dev/null
	else
		result=1
		rm -f $hsh
		logger -t "Storage load" "Invalid storage data in MTD partition: $mtd_part_dev"
	fi
	rm -f $tmp
	rm -f $slk
}

func_tarb()
{
	rm -f $tmp
	cd $dir_storage
	find * -print0 | xargs -0 touch -c -h -t 201001010000.00
	find * ! -type d -print0 | sort -z | xargs -0 tar -cf $tmp 2>/dev/null
	cd - >>/dev/null
	if [ ! -f "$tmp" ] ; then
		logger -t "Storage" "Cannot create tarball file: $tmp"
		exit 1
	fi
}

func_save()
{
	local fsz

	echo "Save storage files to MTD partition \"$mtd_part_dev\""
	rm -f $tbz
	md5sum -c -s $hsh 2>/dev/null
	if [ $? -eq 0 ] ; then
		echo "Storage hash is not changed, skip write to MTD partition. Exit."
		rm -f $tmp
		return 0
	fi
	md5sum $tmp > $hsh
	bzip2 -9 $tmp 2>/dev/null
	fsz=`stat -c %s $tbz 2>/dev/null`
	if [ -n "$fsz" ] && [ $fsz -ge 16 ] && [ $fsz -le $mtd_part_size ] ; then
		mtd_write write $tbz $mtd_part_name
		if [ $? -eq 0 ] ; then
			echo "Done."
		else
			result=1
			echo "Error! MTD write FAILED"
			logger -t "Storage save" "Error write to MTD partition: $mtd_part_dev"
		fi
	else
		result=1
		echo "Error! Invalid storage final data size: $fsz"
		logger -t "Storage save" "Invalid storage final data size: $fsz"
	fi
	rm -f $tmp
	rm -f $tbz
}

func_backup()
{
	rm -f $tbz
	bzip2 -9 $tmp 2>/dev/null
	if [ $? -ne 0 ] ; then
		result=1
		logger -t "Storage backup" "Cannot create BZ2 file!"
	fi
	rm -f $tmp
}

func_restore()
{
	local fsz tmp_storage

	[ ! -f "$tbz" ] && exit 1

	fsz=`stat -c %s $tbz 2>/dev/null`
	if [ -z "$fsz" ] || [ $fsz -lt 16 ] || [ $fsz -gt $mtd_part_size ] ; then
		result=1
		rm -f $tbz
		logger -t "Storage restore" "Invalid BZ2 file size: $fsz"
		return 1
	fi

	tmp_storage="/tmp/storage"
	rm -rf $tmp_storage
	mkdir -p -m 755 $tmp_storage
	tar xjf $tbz -C $tmp_storage 2>/dev/null
	if [ $? -ne 0 ] ; then
		result=1
		rm -f $tbz
		rm -rf $tmp_storage
		logger -t "Storage restore" "Unable to extract BZ2 file: $tbz"
		return 1
	fi
	if [ ! -f "$tmp_storage/start_script.sh" ] ; then
		result=1
		rm -f $tbz
		rm -rf $tmp_storage
		logger -t "Storage restore" "Invalid content of BZ2 file: $tbz"
		return 1
	fi

	func_stop_apps

	rm -f $slk
	rm -f $tbz
	rm -rf $dir_storage
	mkdir -p -m 755 $dir_storage
	cp -rf $tmp_storage /etc
	rm -rf $tmp_storage

	func_start_apps
}

func_erase()
{
	mtd_write erase $mtd_part_name
	if [ $? -eq 0 ] ; then
		rm -f $hsh
		rm -rf $dir_storage
		mkdir -p -m 755 $dir_storage
		touch "$slk"
	else
		result=1
	fi
}

func_reset()
{
	rm -f $slk
	rm -rf $dir_storage
	mkdir -p -m 755 $dir_storage
}

func_fill()
{
	dir_httpssl="$dir_storage/https"
	dir_dnsmasq="$dir_storage/dnsmasq"
	dir_dnsmasq_conf="$dir_storage/dnsmasq/conf.d"
	dir_ovpnsvr="$dir_storage/openvpn/server"
	dir_ovpncli="$dir_storage/openvpn/client"
	dir_sswan="$dir_storage/strongswan"
	dir_sswan_crt="$dir_sswan/ipsec.d"
	dir_inadyn="$dir_storage/inadyn"
	dir_crond="$dir_storage/cron/crontabs"
	dir_wlan="$dir_storage/wlan"
	dir_shadowsocks="$dir_storage/DEADC0DE"
	dir_adbyby="$dir_storage/adb"
	dir_koolproxy="$dir_storage/koolproxy"

	script_start="$dir_storage/start_script.sh"
	script_started="$dir_storage/started_script.sh"
	script_shutd="$dir_storage/shutdown_script.sh"
	script_postf="$dir_storage/post_iptables_script.sh"
	script_postw="$dir_storage/post_wan_script.sh"
	script_inets="$dir_storage/inet_state_script.sh"
	script_vpnsc="$dir_storage/vpns_client_script.sh"
	script_vpncs="$dir_storage/vpnc_server_script.sh"
	script_ezbtn="$dir_storage/ez_buttons_script.sh"
	script_DEADC0DE="$dir_storage/DEADC0DE_script.sh"
	script_adbyby="$dir_storage/adbyby_script.sh"
	script_koolproxy="$dir_storage/koolproxy_script.sh"

	user_hosts="$dir_dnsmasq/hosts"
	user_adblock_hosts="$dir_dnsmasq/adblock.txt"
	user_dnsmasq_conf="$dir_dnsmasq/dnsmasq.conf"
	user_dnsmasq_serv="$dir_dnsmasq/dnsmasq.servers"
	user_ovpnsvr_conf="$dir_ovpnsvr/server.conf"
	user_ovpncli_conf="$dir_ovpncli/client.conf"
	user_inadyn_conf="$dir_inadyn/inadyn.conf"
	user_sswan_conf="$dir_sswan/strongswan.conf"
	user_sswan_ipsec_conf="$dir_sswan/ipsec.conf"
	user_sswan_secrets="$dir_sswan/ipsec.secrets"

	# create crond dir
	[ ! -d "$dir_crond" ] && mkdir -p -m 730 "$dir_crond"

	# create https dir
	[ ! -d "$dir_httpssl" ] && mkdir -p -m 700 "$dir_httpssl"

	# create start script
	if [ ! -f "$script_start" ] ; then
		reset_ss.sh -a
	fi

	# create shadowsocks dir
	[ ! -d "$dir_shadowsocks/dnsmasq.d" ] && mkdir -p -m 755 "$dir_shadowsocks/dnsmasq.d"
	# init gfwlist.conf for dnsmasq
	[ ! -f "$dir_shadowsocks/dnsmasq.d/gfwlist.conf" ] && /usr/sbin/init_gfwlist.sh
	chown 0:0 "$dir_shadowsocks/dnsmasq.d/gfwlist.conf"

	# init chnroute.txt for chinadns
	[ ! -d "$dir_shadowsocks/chnroute" ] && mkdir -p -m 755 "$dir_shadowsocks/chnroute"
	[ ! -f "$dir_shadowsocks/chnroute/chnroute.txt" ] && /usr/sbin/init_chnroute.sh
	chown 0:0 "$dir_shadowsocks/chnroute/chnroute.txt"

    #adbyby
    [ ! -d "$dir_adbyby" ] && mkdir -p -m 755 "$dir_adbyby"
    [ ! -f "$dir_adbyby/80x86_dot_io" ] && touch "$dir_adbyby/80x86_dot_io"
    [ ! -f "$dir_adbyby/80x86.io" ] && ln -sf "$dir_adbyby/80x86_dot_io" "$dir_adbyby/80x86.io"
    [ ! -f "$dir_adbyby/adbybyfirst.sh" ] && /usr/sbin/init_adbyby.sh
    [ ! -s "$dir_adbyby/data/dnsmasq.txt" ] && cp /etc_ro/adbyby.dnsmasq.txt $dir_adbyby/data/dnsmasq.txt
    chown -R 0:0 "$dir_adbyby"

    #koolproxy
    [ ! -d "$dir_koolproxy" ] && mkdir -p -m 755 "$dir_koolproxy"
    [ ! -f "$dir_koolproxy/install.lock" ] && /usr/sbin/koolproxy_init
    [ ! -s "$dir_koolproxy/rules_store/dnsmasq.txt" ] && cp /etc_ro/adbyby.dnsmasq.txt $dir_koolproxy/rules_store/dnsmasq.txt
    touch /etc/storage/koolproxy/install.lock
    chown -R 0:0 "$dir_koolproxy"
    mkdir -p -m 755 /etc/storage/bin

	if [ ! -f "/etc/storage/userList.txt" ] ; then
		cp /etc_ro/userList.txt /etc/storage/userList.txt
	fi

	# create started script
	if [ ! -f "$script_started" ] ; then
		cat > "$script_started" <<EOF
#!/bin/sh

### Custom user script
### Called after router started and network is ready

### Example - load ipset modules
#modprobe ip_set
#modprobe ip_set_hash_ip
#modprobe ip_set_hash_net
#modprobe ip_set_bitmap_ip
#modprobe ip_set_list_set
#modprobe xt_set

EOF
		chmod 755 "$script_started"
	fi

	# create shutdown script
	if [ ! -f "$script_shutd" ] ; then
		cat > "$script_shutd" <<EOF
#!/bin/sh

### Custom user script
### Called before router shutdown
### \$1 - action (0: reboot, 1: halt, 2: power-off)

EOF
		chmod 755 "$script_shutd"
	fi

	# create post-iptables script
	if [ ! -f "$script_postf" ] ; then
		cat > "$script_postf" <<EOF
#!/bin/sh

### Custom user script
### Called after internal iptables reconfig (firewall update)

EOF
		chmod 755 "$script_postf"
	fi

	# create post-wan script
	if [ ! -f "$script_postw" ] ; then
		cat > "$script_postw" <<EOF
#!/bin/sh

### Custom user script
### Called after internal WAN up/down action
### \$1 - WAN action (up/down)
### \$2 - WAN interface name (e.g. eth3 or ppp0)
### \$3 - WAN IPv4 address

EOF
		chmod 755 "$script_postw"
	fi

	# create inet-state script
	if [ ! -f "$script_inets" ] ; then
		cat > "$script_inets" <<EOF
#!/bin/sh

### Custom user script
### Called on Internet status changed
### \$1 - Internet status (0/1)
### \$2 - elapsed time (s) from previous state

logger -t "di" "Internet state: \$1, elapsed time: \$2s."

EOF
		chmod 755 "$script_inets"
	fi

	# create vpn server action script
	if [ ! -f "$script_vpnsc" ] ; then
		cat > "$script_vpnsc" <<EOF
#!/bin/sh

### Custom user script
### Called after remote peer connected/disconnected to internal VPN server
### \$1 - peer action (up/down)
### \$2 - peer interface name (e.g. ppp10)
### \$3 - peer local IP address
### \$4 - peer remote IP address
### \$5 - peer name

peer_if="\$2"
peer_ip="\$4"
peer_name="\$5"

### example: add static route to private LAN subnet behind a remote peer

func_ipup()
{
#  if [ "\$peer_name" == "dmitry" ] ; then
#    route add -net 192.168.5.0 netmask 255.255.255.0 dev \$peer_if
#  elif [ "\$peer_name" == "victoria" ] ; then
#    route add -net 192.168.8.0 netmask 255.255.255.0 dev \$peer_if
#  fi
   return 0
}

func_ipdown()
{
#  if [ "\$peer_name" == "dmitry" ] ; then
#    route del -net 192.168.5.0 netmask 255.255.255.0 dev \$peer_if
#  elif [ "\$peer_name" == "victoria" ] ; then
#    route del -net 192.168.8.0 netmask 255.255.255.0 dev \$peer_if
#  fi
   return 0
}

case "\$1" in
up)
  func_ipup
  ;;
down)
  func_ipdown
  ;;
esac

EOF
		chmod 755 "$script_vpnsc"
	fi

	# create vpn client action script
	if [ ! -f "$script_vpncs" ] ; then
		cat > "$script_vpncs" <<EOF
#!/bin/sh

### Custom user script
### Called after internal VPN client connected/disconnected to remote VPN server
### \$1        - action (up/down)
### \$IFNAME   - tunnel interface name (e.g. ppp5 or tun0)
### \$IPLOCAL  - tunnel local IP address
### \$IPREMOTE - tunnel remote IP address
### \$DNS1     - peer DNS1
### \$DNS2     - peer DNS2

# private LAN subnet behind a remote server (example)
peer_lan="192.168.9.0"
peer_msk="255.255.255.0"

### example: add static route to private LAN subnet behind a remote server

func_ipup()
{
#  route add -net \$peer_lan netmask \$peer_msk gw \$IPREMOTE dev \$IFNAME
   return 0
}

func_ipdown()
{
#  route del -net \$peer_lan netmask \$peer_msk gw \$IPREMOTE dev \$IFNAME
   return 0
}

logger -t vpnc-script "\$IFNAME \$1"

case "\$1" in
up)
  func_ipup
  ;;
down)
  func_ipdown
  ;;
esac

EOF
		chmod 755 "$script_vpncs"
	fi

	# create Ez-Buttons script
	if [ ! -f "$script_ezbtn" ] ; then
		cat > "$script_ezbtn" <<EOF
#!/bin/sh

### Custom user script
### Called on WPS or FN button pressed
### \$1 - button param

[ -x /opt/bin/on_wps.sh ] && /opt/bin/on_wps.sh \$1 &

EOF
		chmod 755 "$script_ezbtn"
	fi

	# create user dnsmasq.conf
	[ ! -d "$dir_dnsmasq" ] && mkdir -p -m 755 "$dir_dnsmasq"
	[ ! -d "$dir_dnsmasq_conf" ] && mkdir -p -m 755 "$dir_dnsmasq_conf"
	[ -d "$dir_dnsmasq_conf" ] && touch "$dir_dnsmasq_conf/.keepme"
	for i in dnsmasq.conf hosts ; do
		[ -f "$dir_storage/$i" ] && mv -n "$dir_storage/$i" "$dir_dnsmasq"
	done
	if [ ! -f "$user_dnsmasq_conf" ] ; then
		cat > "$user_dnsmasq_conf" <<EOF
# Custom user conf file for dnsmasq
# Please add needed params only!

### Web Proxy Automatic Discovery (WPAD)
dhcp-option=252,"\n"

### Set the limit on DHCP leases, the default is 150
#dhcp-lease-max=150

### Add local-only domains, queries are answered from hosts or DHCP only
#local=/router/localdomain/

### Examples:

### Enable built-in TFTP server
#enable-tftp

### Set the root directory for files available via TFTP.
#tftp-root=/opt/srv/tftp

### Make the TFTP server more secure
#tftp-secure

### Set the boot filename for netboot/PXE
#dhcp-boot=pxelinux.0

### Add extra hosts file
#addn-hosts=/etc/storage/dnsmasq/other_hosts.txt
EOF
		chmod 644 "$user_dnsmasq_conf"
	fi

	# create user dns servers
	if [ ! -f "$user_dnsmasq_serv" ] ; then
		cat > "$user_dnsmasq_serv" <<EOF
# Custom user servers file for dnsmasq
# Example:
#server=/mit.ru/izmuroma.ru/10.25.11.30

#resolve update.adbyby.com via 114 public DNS
#server=/update.adbyby.com/114.114.114.114
#resolve koolproxy rule udpate domain via dnspod public DNS
#server=/koolproxy.com/114.114.114.114
#server=/kprule.com/114.114.114.114
#optimize .cn domain
#server=/cn/114.114.114.114
EOF
		chmod 644 "$user_dnsmasq_serv"
	fi

	# create user inadyn.conf"
	[ ! -d "$dir_inadyn" ] && mkdir -p -m 755 "$dir_inadyn"
	if [ ! -f "$user_inadyn_conf" ] ; then
		cat > "$user_inadyn_conf" <<EOF
# Custom user conf file for inadyn DDNS client
# Please add only new custom system!

### Example for twoDNS.de:

#system custom@http_srv_basic_auth
#  ssl
#  checkip-url checkip.two-dns.de /
#  server-name update.twodns.de
#  server-url /update\?hostname=
#  username account
#  password secret
#  alias example.dd-dns.de

EOF
		chmod 644 "$user_inadyn_conf"
	fi

	# create user hosts
	if [ ! -f "$user_hosts" ] ; then
		cat > "$user_hosts" <<EOF
# Custom user hosts file
# Example:
# 192.168.1.100		Boo

#uncomment below to fuck thunder
#0.0.0.0 hub5btmain.sandai.net
#0.0.0.0 hub5emu.sandai.net
#0.0.0.0 upgrade.xl9.xunlei.com
#0.0.0.0 liveupdate.mac.sandai.net
EOF
		chmod 644 "$user_hosts"
	fi

	# create adblock hosts
	if [ ! -f "$user_adblock_hosts" ] ; then
		cat > "$user_adblock_hosts" <<EOF
# Custom user adblock hosts file
EOF
		chmod 644 "$user_adblock_hosts"
	fi

	# create user AP confs
	[ ! -d "$dir_wlan" ] && mkdir -p -m 755 "$dir_wlan"
	if [ ! -f "$dir_wlan/AP.dat" ] ; then
		cat > "$dir_wlan/AP.dat" <<EOF
# Custom user AP conf file

EOF
		chmod 644 "$dir_wlan/AP.dat"
	fi

	if [ ! -f "$dir_wlan/AP_5G.dat" ] ; then
		cat > "$dir_wlan/AP_5G.dat" <<EOF
# Custom user AP conf file

EOF
		chmod 644 "$dir_wlan/AP_5G.dat"
	fi

	# create openvpn files
	if [ -x /usr/sbin/openvpn ] ; then
		[ ! -d "$dir_ovpncli" ] && mkdir -p -m 700 "$dir_ovpncli"
		[ ! -d "$dir_ovpnsvr" ] && mkdir -p -m 700 "$dir_ovpnsvr"
		dir_ovpn="$dir_storage/openvpn"
		for i in ca.crt dh1024.pem server.crt server.key server.conf ta.key ; do
			[ -f "$dir_ovpn/$i" ] && mv -n "$dir_ovpn/$i" "$dir_ovpnsvr"
		done
		if [ ! -f "$user_ovpnsvr_conf" ] ; then
			cat > "$user_ovpnsvr_conf" <<EOF
# Custom user conf file for OpenVPN server
# Please add needed params only!

### Max clients limit
max-clients 10

### Internally route client-to-client traffic
client-to-client

### Allow clients with duplicate "Common Name"
;duplicate-cn

### Keepalive and timeout
keepalive 10 60

### Process priority level (0..19)
nice 3

### Syslog verbose level
verb 0
mute 10

### openvpn_xorpatch
# see https://tunnelblick.net/cOpenvpn_xorpatch.html for more information
# Note: The "scramble" option and parameters in the server and client configuration files must match.
#scramble put_your_xor_string_here

EOF
			chmod 644 "$user_ovpnsvr_conf"
		fi

		if [ ! -f "$user_ovpncli_conf" ] ; then
			cat > "$user_ovpncli_conf" <<EOF
# Custom user conf file for OpenVPN client
# Please add needed params only!

### If your server certificates with the nsCertType field set to "server"
ns-cert-type server

### Process priority level (0..19)
nice 0

### Syslog verbose level
verb 0
mute 10

### openvpn_xorpatch
# see https://tunnelblick.net/cOpenvpn_xorpatch.html for more information
# Note: The "scramble" option and parameters in the server and client configuration files must match.
#scramble put_your_xor_string_here

EOF
			chmod 644 "$user_ovpncli_conf"
		fi
	fi

	#shadowsocks
	if [ ! -s "$script_DEADC0DE" ] ; then
	cat > "$script_DEADC0DE" <<EOF
#! /bin/sh
#
# GoogleFu user script
# Called after GoogleFu started and GoogleFu is stoped
#
# Copyright (C) 2016 sh4d0walker <sh4d0walker@Sh4d0Walker-Arch-i7>
#
# Distributed under terms of the MIT license.
#

### \$1 - action (start/stop)

ss_script_debug=0
ss_enable=\$(nvram get shadowsocks_enable)
ss_mode=\$(nvram get shadowsocks_mode)
ss_sever=\$(nvram get ss_current_node_addr)
ss_redir_port=\$(nvram get ss_redir_port)
ss_udp=\$(nvram get shadowsocks_udp)
foreign_dns=\$(nvram get current_foreign_dns)
foreign_dns_port=\$(nvram get current_foreign_dns_port)
dns_provider=\$(nvram get shadowsocks_dns_provider)
ss_tcp_detect_ip=\$(nvram get ss_tcp_detect_ip)
wan0_ipaddr=\$(nvram get wan0_ipaddr)
dnsmasq_user_conf=/etc/storage/dnsmasq/dnsmasq.conf
if [ "\$dns_provider" == "0" ];then
	dnsmasq_foreign_dns="\${foreign_dns}#\${foreign_dns_port}"
else
    dnsmasq_foreign_dns="127.0.0.1#5353"
fi

#ref to https://en.wikipedia.org/wiki/Reserved_IP_addresses
func_get_reserved_ip_addr() {
	cat <<-EOF
		\$ss_sever
		0.0.0.0/8
		10.0.0.0/8
		100.64.0.0/10
		127.0.0.0/8
		169.254.0.0/16
		172.16.0.0/12
		192.0.0.0/24
		192.0.2.0/24
		192.31.196.0/24
		192.52.193.0/24
		192.88.99.0/24
		192.168.0.0/16
		192.175.48.0/24
		198.18.0.0/15
		198.51.100.0/24
		203.0.113.0/24
		224.0.0.0/4
		240.0.0.0/4
		255.255.255.255/32
$EOF_STR
}

func_ss_started()
{
    logger -t "[script_DEADC0DE]" " ==== ss_started ===="
    lsmod | grep -q '^ip_set ' || modprobe ip_set
    lsmod | grep -q '^ip_set_hash_ip ' || modprobe ip_set_hash_ip
    lsmod | grep -q '^ip_set_hash_net ' || modprobe ip_set_hash_net
    lsmod | grep -q '^ip_set_bitmap_ip ' || modprobe ip_set_bitmap_ip
    lsmod | grep -q '^ip_set_list_set ' || modprobe ip_set_list_set
    lsmod | grep -q '^xt_set ' || modprobe xt_set

	#ensure file exists
	touch $dir_shadowsocks/dnsmasq.d/dst_bp.txt
	touch $dir_shadowsocks/dnsmasq.d/src_bp.txt
	touch $dir_shadowsocks/dnsmasq.d/custom_rules.txt
	touch $dir_shadowsocks/chnroute/chnroute_tun.txt

    if [ \$ss_mode == "1" ];then
		#only for gfwlist mode
		ln -sf $dir_shadowsocks/dnsmasq.d/gfwlist.conf $dir_dnsmasq_conf/
    fi

    ipset -exist create extra_dst_bp hash:net hashsize 64
    ipset -exist create extra_src_bp hash:net hashsize 64
    sed -Ee '/^#/d' $dir_shadowsocks/dnsmasq.d/dst_bp.txt | awk 'NF' | grep -E "^([0-9]{1,3}\.){3}[0-9]{1,3}" | sed -e "s/^/add extra_dst_bp /" | ipset restore
    sed -Ee '/^#/d' $dir_shadowsocks/dnsmasq.d/dst_bp.txt | awk 'NF' | grep -vE "^([0-9]{1,3}\.){3}[0-9]{1,3}" | sed -e "s/^/ipset=\//" | sed -e "s/$/\/extra_dst_bp/" > $dir_dnsmasq_conf/extra_dst_bp.conf
    sed -Ee '/^#/d' $dir_shadowsocks/dnsmasq.d/src_bp.txt | awk 'NF' | grep -E "^([0-9]{1,3}\.){3}[0-9]{1,3}" | sed -e "s/^/add extra_src_bp /" | ipset restore

    logger -t "[script_DEADC0DE]" "create 0X8BADF00D chain in nat table..."
#    iptables -t nat -N 0X8BADF00D
	iptables-restore -n <<-EOF
	*nat
	:0X8BADF00D - [0:0]
	\$(func_get_reserved_ip_addr | sed -e "s/\(.*\)/-A 0X8BADF00D -d \1 -j RETURN/")
	COMMIT
$EOF_STR
    iptables -t nat -A 0X8BADF00D -m set --match-set extra_dst_bp dst -j RETURN
    iptables -t nat -A 0X8BADF00D -m set --match-set extra_src_bp src -j RETURN
    [ \$ss_script_debug == "1" ] && iptables -L 0X8BADF00D  -v -n -t nat

    #udp support
    if [ \$ss_udp == "1" ];then
        lsmod | grep -q '^xt_TPROXY ' || modprobe xt_TPROXY
        ip rule add fwmark 0x01/0x01 table 100
        ip route add local 0.0.0.0/0 dev lo table 100
#        iptables -t mangle -N 0X8BADF00D
		iptables-restore -n <<-EOF
		*mangle
		:0X8BADF00D - [0:0]
		\$(func_get_reserved_ip_addr | sed -e "s/\(.*\)/-A 0X8BADF00D -d \1 -j RETURN/")
		COMMIT
$EOF_STR
	    iptables -t mangle -A 0X8BADF00D -m set --match-set extra_dst_bp dst -j RETURN
	    iptables -t mangle -A 0X8BADF00D -m set --match-set extra_src_bp src -j RETURN
	    [ \$ss_script_debug == "1" ] && iptables -L 0X8BADF00D  -v -n -t mangle
    fi

    case \$ss_mode in
    "1")
        logger -t "[script_DEADC0DE]" "ipset: create gfwlist"
    	ipset -exist create gfwlist hash:ip counters timeout 1200
    	sed -Ei "s/([0-9]{1,3}\.){3}[0-9]{1,3}#[0-9]{1,6}/\${dnsmasq_foreign_dns}/"  $dir_shadowsocks/dnsmasq.d/gfwlist.conf
    	ipset -exist create extra_gfwlist_rules hash:net counters timeout 1200
    	grep -q blogger.com $dir_shadowsocks/dnsmasq.d/custom_rules.txt || echo blogger.com >> $dir_shadowsocks/dnsmasq.d/custom_rules.txt
    	grep -q 'gfwlist force IP' $dir_shadowsocks/dnsmasq.d/custom_rules.txt || cat /etc_ro/force_proxy_ip.txt >> $dir_shadowsocks/dnsmasq.d/custom_rules.txt
        sed -Ee '/^#/d' $dir_shadowsocks/dnsmasq.d/custom_rules.txt | awk 'NF' | grep -v -E "^([0-9]{1,3}\.){3}[0-9]{1,3}" | sed -e "s/^/ipset=\//" | sed -e "s/$/\/extra_gfwlist_rules/" > $dir_dnsmasq_conf/extra_gfwlist_rules.conf
        sed -Ee '/^#/d' $dir_shadowsocks/dnsmasq.d/custom_rules.txt | awk 'NF' | grep -v -E "^([0-9]{1,3}\.){3}[0-9]{1,3}" | sed -e "s/^/server=\//" | sed -e "s/$/\/\${dnsmasq_foreign_dns}/" >> $dir_dnsmasq_conf/extra_gfwlist_rules.conf
        sed -Ee '/^#/d' $dir_shadowsocks/dnsmasq.d/custom_rules.txt | awk 'NF' | grep -E "^([0-9]{1,3}\.){3}[0-9]{1,3}" | sed -e "s/^/add extra_gfwlist_rules /" | ipset restore
        ;;
    "2")
        logger -t "[script_DEADC0DE]" "ipset: create list"
    	ipset -exist create chnroute hash:net hashsize 64
    	ipset -exist create chnroute_tun hash:net hashsize 64
    	sed -e "s/^/add chnroute /" $dir_shadowsocks/chnroute/chnroute.txt | ipset restore
    	#ip set that always to ss tun
    	[ -s $dir_shadowsocks/chnroute/chnroute_tun.txt ] && sed -e "s/^/add chnroute_tun /" $dir_shadowsocks/chnroute/chnroute_tun.txt | ipset restore
        ;;
    esac

    case \$ss_mode in
    "0")
        iptables -t nat -A 0X8BADF00D -p tcp -d \$foreign_dns -j REDIRECT --to-port \$ss_redir_port
        logger -t "[script_DEADC0DE]" "redirect all traffic to \$ss_redir_port"
        iptables -t nat -A 0X8BADF00D -p tcp -j REDIRECT --to-port \$ss_redir_port
        ;;
    "1")
        logger -t "[script_DEADC0DE]" "redirect match-set gfwlist dst to \$ss_redir_port"
        #8888 in ipset will timeout in 1200 seconds
        iptables -t nat -A 0X8BADF00D -p tcp -d \$foreign_dns -j REDIRECT --to-port \$ss_redir_port
        iptables -t nat -A 0X8BADF00D -p tcp -m set --match-set gfwlist dst -j REDIRECT --to-port \$ss_redir_port
        iptables -t nat -A 0X8BADF00D -p tcp -m set --match-set extra_gfwlist_rules dst -j REDIRECT --to-port \$ss_redir_port
        /sbin/ipset flush gfwlist
        if [ "z\$ss_tcp_detect_ip" != "z" ];then
            /sbin/ipset add gfwlist \$ss_tcp_detect_ip
        fi
        ;;
	"2")
		iptables -t nat -A 0X8BADF00D -p tcp -m set --match-set chnroute_tun dst -j REDIRECT --to-port \$ss_redir_port
        logger -t "[script_DEADC0DE]" "bypass match-set chnroute dst"
        iptables -t nat -A 0X8BADF00D -m set --match-set chnroute dst -j RETURN
        iptables -t nat -A 0X8BADF00D -p tcp -j REDIRECT --to-port \$ss_redir_port
        ;;
    esac

    #udp support
    if [ \$ss_udp == "1" ];then
        case \$ss_mode in
        "0")
            logger -t "[script_DEADC0DE]" "redirect all traffic to \$ss_redir_port"
            iptables -t mangle -A 0X8BADF00D -p udp -j TPROXY --on-port \$ss_redir_port --tproxy-mark 0x01/0x01
            /sbin/ipset flush gfwlist
            ;;
        "1")
            logger -t "[script_DEADC0DE]" "redirect match-set gfwlist dst to \$ss_redir_port"
            #8888 in ipset will timeout in 1200 seconds
            iptables -t mangle -A 0X8BADF00D -p udp -d \$foreign_dns -j TPROXY --on-port \$ss_redir_port --tproxy-mark 0x01/0x01
            iptables -t mangle -A 0X8BADF00D -p udp -m set --match-set gfwlist dst -j TPROXY --on-port \$ss_redir_port --tproxy-mark 0x01/0x01
            iptables -t mangle -A 0X8BADF00D -p udp -m set --match-set extra_gfwlist_rules dst -j TPROXY --on-port \$ss_redir_port --tproxy-mark 0x01/0x01
            /sbin/ipset flush gfwlist
            ;;
        "2")
            iptables -t mangle -A 0X8BADF00D -p udp -m set --match-set chnroute_tun dst -j TPROXY --on-port \$ss_redir_port --tproxy-mark 0x01/0x01
            logger -t "[script_DEADC0DE]" "bypass match-set chnroute dst"
            iptables -t mangle -A 0X8BADF00D -m set --match-set chnroute dst -j RETURN
            iptables -t mangle -A 0X8BADF00D -p udp -j TPROXY --on-port \$ss_redir_port --tproxy-mark 0x01/0x01
            ;;
        esac
    fi

    logger -t "[script_DEADC0DE]" "nat to 0X8BADF00D chain"
    #for router
    adb_prerouting_index=\$(iptables -t nat -L PREROUTING -v -n --line-numbers | grep ADBYBY_RULE | cut -d " " -f 1 | sort -nr | head -n1)
    kp_prerouting_index=\$(iptables -t nat -L PREROUTING -v -n --line-numbers | grep KOOLPROXY_RULE | cut -d " " -f 1 | sort -nr | head -n1)
    target_index=\$adb_prerouting_index
    [ "\$target_index" == "" ] && target_index=\$kp_prerouting_index
    if [ "\$target_index" == "" ]; then
        iptables -t nat -A PREROUTING -p tcp -j 0X8BADF00D
    else
        iptables -t nat -I PREROUTING \$target_index -p tcp -j 0X8BADF00D
    fi

    #for pc self
    iptables -t nat -A OUTPUT -p tcp -j 0X8BADF00D

    #udp support, TPROXY can not apply to OUTPUT chain
    if [ \$ss_udp == "1" ];then
        iptables -t mangle -A PREROUTING -p udp -j 0X8BADF00D
    fi

    /sbin/restart_dhcpd
    logger -t "[script_DEADC0DE]" "Done start."
}

func_ss_stoped()
{
    logger -t "[script_DEADC0DE]" " ==== ss_stoped ===="
    # rules index
    prerouting_index=\$(iptables -t nat -L PREROUTING -v -n --line-numbers | grep 0X8BADF00D | cut -d " " -f 1 | sort -nr | head -n1)
    output_index=\$(iptables -t nat -L OUTPUT -v -n --line-numbers | grep 0X8BADF00D | cut -d " " -f 1 | sort -nr | head -n1)
    iptables -t nat -D PREROUTING \$prerouting_index  >/dev/null 2>&1
    iptables -t nat -D OUTPUT \$output_index  >/dev/null 2>&1
    /bin/iptables -t nat -F 0X8BADF00D >/dev/null 2>&1
    /bin/iptables -t nat -X 0X8BADF00D >/dev/null 2>&1

    #mangle
    prerouting_index=\$(iptables -t mangle -L PREROUTING -v -n --line-numbers | grep 0X8BADF00D | cut -d " " -f 1 | sort -nr | head -n1)
    iptables -t mangle -D PREROUTING \$prerouting_index  >/dev/null 2>&1
    /bin/iptables -t mangle -F 0X8BADF00D >/dev/null 2>&1
    /bin/iptables -t mangle -X 0X8BADF00D >/dev/null 2>&1

    ip rule delete fwmark 0x01/0x01 table 100 >/dev/null 2>&1
    ip route delete local 0.0.0.0/0 dev lo table 100 >/dev/null 2>&1

    rm -f $dir_dnsmasq_conf/gfwlist.conf &>/dev/null
    rm -f $dir_dnsmasq_conf/extra_dst_bp.conf &>/dev/null
    rm -f $dir_dnsmasq_conf/extra_gfwlist_rules.conf &>/dev/null
    #we restart dnsmasq in start func...
    if [ "\$ss_enable" != "1" ]; then
        /sbin/restart_dhcpd
    fi
    /sbin/ipset destroy gfwlist >/dev/null 2>&1
    /sbin/ipset destroy chnroute >/dev/null 2>&1
    /sbin/ipset destroy chnroute_tun >/dev/null 2>&1
    /sbin/ipset destroy extra_dst_bp >/dev/null 2>&1
    /sbin/ipset destroy extra_src_bp >/dev/null 2>&1
    /sbin/ipset destroy extra_gfwlist_rules >/dev/null 2>&1
    logger -t "[script_DEADC0DE]" "Done stop."
}

case "\$1" in
	start)
		func_ss_started
		;;
	stop)
		func_ss_stoped
		;;
esac

EOF
    chmod 755 "$script_DEADC0DE"
	fi

    if [ ! -s "$script_adbyby" ]; then
    cat > "$script_adbyby" <<EOF
#!/bin/sh
#
# adbyby_script.sh
# Copyright (C) 2016 sh4d0walker <sh4d0walker@HuangYe>
#
# Distributed under terms of the MIT license.
#

adbyby_enable=\$(nvram get adbyby_enable)
adbyby_filter_port=\$(nvram get adbyby_filter_port)
adbyby_listen_port=\$(nvram get adbyby_listen_port)
cur_datetime=\$(date "+%Y-%m-%d %H:%M:%S")
adbyby_mode=\$(nvram get adbyby_mode)
rom_api_server_addr=\$(nvram get rom_api_server_addr)

func_adbyby_start()
{
    lsmod | grep -q '^ip_set ' || modprobe ip_set
    lsmod | grep -q '^ip_set_hash_ip ' || modprobe ip_set_hash_ip
    lsmod | grep -q '^ip_set_hash_net ' || modprobe ip_set_hash_net
    lsmod | grep -q '^ip_set_bitmap_ip ' || modprobe ip_set_bitmap_ip
    lsmod | grep -q '^ip_set_list_set ' || modprobe ip_set_list_set
    lsmod | grep -q '^xt_set ' || modprobe xt_set

	# Ad-list mode
    if [ \$adbyby_mode == "1" ];then
        ipset -exist create adbyby hash:ip counters timeout 1200
        [ ! -s "$dir_koolproxy/rules_store/dnsmasq.txt" ] && cp /etc_ro/adbyby.dnsmasq.txt $dir_koolproxy/rules_store/dnsmasq.txt
        sed -Ee '/^#/d' $dir_adbyby/data/dnsmasq.txt | awk 'NF' | sed -e "s/^/ipset=\//" | sed -e "s/$/\/adbyby/" > $dir_dnsmasq_conf/adbyby.conf
        /sbin/restart_dhcpd
    fi
    ipset -exist create adbyby_dst_bp hash:net hashsize 64
    if [ -f "$dir_adbyby/data/dst_bp.ip.txt" ] ; then
        sed -Ee '/^#/d' $dir_adbyby/data/dst_bp.ip.txt | awk 'NF' | sed -e "s/^/add adbyby_dst_bp /" | ipset restore
    fi

	echo "\$cur_datetime [adbyby] start ..." >> /tmp/adbyby.log
	iptables -t nat -N ADBYBY_RULE >/dev/null 2>&1
	iptables -t nat -A ADBYBY_RULE -d \$rom_api_server_addr -j RETURN
	iptables -t nat -A ADBYBY_RULE -d 0.0.0.0/8 -j RETURN
	iptables -t nat -A ADBYBY_RULE -d 10.0.0.0/8 -j RETURN
	iptables -t nat -A ADBYBY_RULE -d 127.0.0.0/8 -j RETURN
	iptables -t nat -A ADBYBY_RULE -d 169.254.0.0/16 -j RETURN
	iptables -t nat -A ADBYBY_RULE -d 172.16.0.0/12 -j RETURN
	iptables -t nat -A ADBYBY_RULE -d 192.168.0.0/16 -j RETURN
	iptables -t nat -A ADBYBY_RULE -d 224.0.0.0/4 -j RETURN
	iptables -t nat -A ADBYBY_RULE -d 240.0.0.0/4 -j RETURN
	iptables -t nat -A ADBYBY_RULE -m set --match-set adbyby_dst_bp dst -j RETURN
	if [ \$adbyby_mode == "1" ];then
		iptables -t nat -A ADBYBY_RULE -p tcp -m set --match-set adbyby dst -j REDIRECT --to-ports \$adbyby_listen_port
	else
		iptables -t nat -A ADBYBY_RULE -p tcp -j REDIRECT --to-ports \$adbyby_listen_port
	fi
}

func_adbyby_stop()
{
    echo "\$cur_datetime [adbyby] stop ..." >> /tmp/adbyby.log
    iptables -t nat -F ADBYBY_RULE >/dev/null 2>&1
    #iptables -t nat -X ADBYBY_RULE >/dev/null 2>&1
    prerouting_index=\$(iptables -t nat -L PREROUTING -v -n --line-numbers | grep ADBYBY_RULE | cut -d " " -f 1 | sort -nr | head -n1)
    iptables -t nat -D PREROUTING \$prerouting_index  >/dev/null 2>&1
    ipset flush adbyby_dst_bp >/dev/null 2>&1
    ipset destroy adbyby_dst_bp >/dev/null 2>&1

	[ -f "$dir_dnsmasq_conf/adbyby.conf" ] && rm -f $dir_dnsmasq_conf/adbyby.conf &>/dev/null
	if [ "\$adbyby_enable" != "1" ]; then
	    /sbin/restart_dhcpd
    fi
}

case "\$1" in
	start)
		func_adbyby_start
		;;
	stop)
		func_adbyby_stop
		;;
esac

EOF
    chmod 755 "$script_adbyby"
    fi

    if [ ! -s "$script_koolproxy" ]; then
    cat > "$script_koolproxy" <<EOF
#!/bin/sh
#
# koolproxy_script.sh
# Copyright (C) 2016 sh4d0walker <sh4d0walker@HuangYe>
#
# Distributed under terms of the MIT license.
#

koolproxy_enable=\$(nvram get koolproxy_enable)
koolproxy_filter_port=\$(nvram get koolproxy_filter_port)
koolproxy_listen_port=\$(nvram get koolproxy_listen_port)
cur_datetime=\$(date "+%Y-%m-%d %H:%M:%S")
koolproxy_mode=\$(nvram get koolproxy_mode)
rom_api_server_addr=\$(nvram get rom_api_server_addr)

func_koolproxy_start()
{
    lsmod | grep -q '^ip_set ' || modprobe ip_set
    lsmod | grep -q '^ip_set_hash_ip ' || modprobe ip_set_hash_ip
    lsmod | grep -q '^ip_set_hash_net ' || modprobe ip_set_hash_net
    lsmod | grep -q '^ip_set_bitmap_ip ' || modprobe ip_set_bitmap_ip
    lsmod | grep -q '^ip_set_list_set ' || modprobe ip_set_list_set
    lsmod | grep -q '^xt_set ' || modprobe xt_set

	# Ad-list mode
    if [ \$koolproxy_mode == "1" ];then
        ipset -exist create koolproxy hash:ip counters timeout 1200
        sed -Ee '/^#/d' $dir_koolproxy/rules_store/dnsmasq.txt | awk 'NF' | sed -e "s/^/ipset=\//" | sed -e "s/$/\/koolproxy/" > $dir_dnsmasq_conf/koolproxy.conf
        /sbin/restart_dhcpd
    fi
    ipset -exist create koolproxy_dst_bp hash:net hashsize 64
    ipset -exist create koolproxy_src_bp hash:net hashsize 64
    if [ -f "$dir_koolproxy/rules_store/dst_bp.txt" ] ; then
        sed -Ee '/^#/d' $dir_koolproxy/rules_store/dst_bp.txt | awk 'NF' | sed -e "s/^/add koolproxy_dst_bp /" | ipset restore
    fi
    if [ -f "$dir_koolproxy/rules_store/src_bp.txt" ] ; then
        sed -Ee '/^#/d' $dir_koolproxy/rules_store/src_bp.txt | awk 'NF' | sed -e "s/^/add koolproxy_src_bp /" | ipset restore
    fi

	echo "\$cur_datetime [koolproxy] start ..." >> /tmp/koolproxy.log
	iptables -t nat -N KOOLPROXY_RULE >/dev/null 2>&1
	iptables -t nat -A KOOLPROXY_RULE -d \$rom_api_server_addr -j RETURN
	iptables -t nat -A KOOLPROXY_RULE -d rules.ngrok.wang -j RETURN
	iptables -t nat -A KOOLPROXY_RULE -d 0.0.0.0/8 -j RETURN
	iptables -t nat -A KOOLPROXY_RULE -d 10.0.0.0/8 -j RETURN
	iptables -t nat -A KOOLPROXY_RULE -d 127.0.0.0/8 -j RETURN
	iptables -t nat -A KOOLPROXY_RULE -d 169.254.0.0/16 -j RETURN
	iptables -t nat -A KOOLPROXY_RULE -d 172.16.0.0/12 -j RETURN
	iptables -t nat -A KOOLPROXY_RULE -d 192.168.0.0/16 -j RETURN
	iptables -t nat -A KOOLPROXY_RULE -d 224.0.0.0/4 -j RETURN
	iptables -t nat -A KOOLPROXY_RULE -d 240.0.0.0/4 -j RETURN
	iptables -t nat -A KOOLPROXY_RULE -m set --match-set koolproxy_dst_bp dst -j RETURN
	iptables -t nat -A KOOLPROXY_RULE -m set --match-set koolproxy_src_bp src -j RETURN

	if [ \$koolproxy_mode == "1" ];then
		iptables -t nat -A KOOLPROXY_RULE -p tcp -m set --match-set koolproxy dst -j REDIRECT --to-ports \$koolproxy_listen_port
	else
		iptables -t nat -A KOOLPROXY_RULE -p tcp -j REDIRECT --to-ports \$koolproxy_listen_port
	fi
	#empty value will cause write_textarea_to_file unlink our symbolic link
	test -s $dir_koolproxy/data/ca.crt || ln -sf $dir_koolproxy/data/certs/ca.crt $dir_koolproxy/data/ca.crt
	test -s $dir_koolproxy/data/ca.key.pem || ln -sf $dir_koolproxy/data/private/ca.key.pem $dir_koolproxy/data/ca.key.pem
	test -s $dir_koolproxy/data/base.key.pem || ln -sf $dir_koolproxy/data/private/base.key.pem $dir_koolproxy/data/base.key.pem
}

func_koolproxy_stop()
{
    echo "\$cur_datetime [koolproxy] stop ..." >> /tmp/koolproxy.log
    iptables -t nat -F KOOLPROXY_RULE >/dev/null 2>&1
    #iptables -t nat -X KOOLPROXY_RULE >/dev/null 2>&1
    prerouting_index=\$(iptables -t nat -L PREROUTING -v -n --line-numbers | grep KOOLPROXY_RULE | cut -d " " -f 1 | sort -nr | head -n1)
    iptables -t nat -D PREROUTING \$prerouting_index  >/dev/null 2>&1
    ipset flush koolproxy_dst_bp >/dev/null 2>&1
    ipset destroy koolproxy_dst_bp >/dev/null 2>&1
    ipset flush koolproxy_src_bp >/dev/null 2>&1
    ipset destroy koolproxy_src_bp >/dev/null 2>&1

	[ -f "$dir_dnsmasq_conf/koolproxy.conf" ] && rm -f $dir_dnsmasq_conf/koolproxy.conf &>/dev/null
	if [ "\$koolproxy_enable" != "1" ]; then
	    /sbin/restart_dhcpd
    fi
}

case "\$1" in
	start)
		func_koolproxy_start
		;;
	stop)
		func_koolproxy_stop
		;;
esac
EOF
    chmod 755 "$script_koolproxy"
    fi

	# create strongswan files
	if [ -x /usr/sbin/ipsec ] ; then
		[ ! -d "$dir_sswan" ] && mkdir -p -m 700 "$dir_sswan"
		[ ! -d "$dir_sswan_crt" ] && mkdir -p -m 700 "$dir_sswan_crt"
		[ ! -d "$dir_sswan_crt/cacerts" ] && mkdir -p -m 700 "$dir_sswan_crt/cacerts"
		[ ! -d "$dir_sswan_crt/certs" ] && mkdir -p -m 700 "$dir_sswan_crt/certs"
		[ ! -d "$dir_sswan_crt/private" ] && mkdir -p -m 700 "$dir_sswan_crt/private"

		if [ ! -f "$user_sswan_conf" ] ; then
			cat > "$user_sswan_conf" <<EOF
### strongswan.conf - user strongswan configuration file

EOF
			chmod 644 "$user_sswan_conf"
		fi
		if [ ! -f "$user_sswan_ipsec_conf" ] ; then
			cat > "$user_sswan_ipsec_conf" <<EOF
### ipsec.conf - user strongswan IPsec configuration file

EOF
			chmod 644 "$user_sswan_ipsec_conf"
		fi
		if [ ! -f "$user_sswan_secrets" ] ; then
			cat > "$user_sswan_secrets" <<EOF
### ipsec.secrets - user strongswan IPsec secrets file

EOF
			chmod 644 "$user_sswan_secrets"
		fi
	fi
}

case "$1" in
load)
	func_get_mtd
	func_mdir
	func_load
	;;
save)
	[ -f "$slk" ] && exit 1
	func_get_mtd
	func_mdir
	func_tarb
	func_save
	;;
backup)
	func_get_mtd
	func_mdir
	func_tarb
	func_backup
	;;
restore)
	func_get_mtd
	func_restore
	;;
erase)
	func_get_mtd
	func_erase
	;;
reset)
	func_stop_apps
	func_reset
	func_fill
	func_start_apps
	;;
fill)
	func_mdir
	func_fill
	;;
*)
	echo "Usage: $0 {load|save|backup|restore|erase|reset|fill}"
	exit 1
	;;
esac

exit $result
