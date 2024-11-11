#!/bin/bash

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'
 
# check root
[[ $EUID -ne 0 ]] && echo -e "${red}Error：${plain} This script must be run with the root user！\n" && exit 1

# check os
if [[ -f /etc/redhat-release ]]; then
    release="centos"
elif cat /etc/issue | grep -Eqi "debian"; then
    release="debian"
elif cat /etc/issue | grep -Eqi "ubuntu"; then
    release="ubuntu"
elif cat /etc/issue | grep -Eqi "centos|red hat|redhat"; then
    release="centos"
elif cat /proc/version | grep -Eqi "debian"; then
    release="debian"
elif cat /proc/version | grep -Eqi "ubuntu"; then
    release="ubuntu"
elif cat /proc/version | grep -Eqi "centos|red hat|redhat"; then
    release="centos"
else
    echo -e "${red}System version not detected, please contact the script author！${plain}\n" && exit 1
fi

arch=$(uname -m)
kernelArch=$arch
case $arch in
	"i386" | "i686")
		kernelArch=32
		;;
	"x86_64" | "amd64" | "x64")
		kernelArch=64
		;;
	"arm64" | "armv8l" | "aarch64")
		kernelArch="arm64-v8a"
		;;
esac

echo "arch: ${kernelArch}"

os_version=""

# os version
if [[ -f /etc/os-release ]]; then
    os_version=$(awk -F'[= ."]' '/VERSION_ID/{print $3}' /etc/os-release)
fi
if [[ -z "$os_version" && -f /etc/lsb-release ]]; then
    os_version=$(awk -F'[= ."]+' '/DISTRIB_RELEASE/{print $2}' /etc/lsb-release)
fi

if [[ x"${release}" == x"centos" ]]; then
    if [[ ${os_version} -le 6 ]]; then
        echo -e "${red}Please use CentOS 7 or later!${plain}\n" && exit 1
    fi
elif [[ x"${release}" == x"ubuntu" ]]; then
    if [[ ${os_version} -lt 16 ]]; then
        echo -e "${red}Please use Ubuntu 16 or later system！${plain}\n" && exit 1
    fi
elif [[ x"${release}" == x"debian" ]]; then
    if [[ ${os_version} -lt 8 ]]; then
        echo -e "${red}Please use Debian 8 or higher！${plain}\n" && exit 1
    fi
fi

install_base() {
    if [[ x"${release}" == x"centos" ]]; then
        yum install epel-release -y
        yum install wget curl unzip tar crontabs socat -y
    else
        apt update -y
        apt install wget curl unzip tar cron socat -y
    fi
}

# 0: running, 1: not running, 2: not installed
check_status() {
    if [[ ! -f /etc/systemd/system/XMPlus.service ]]; then
        return 2
    fi
    temp=$(systemctl status XMPlus | grep Active | awk '{print $3}' | cut -d "(" -f2 | cut -d ")" -f1)
    if [[ x"${temp}" == x"running" ]]; then
        return 0
    else
        return 1
    fi
}

install_acme() {
    curl https://get.acme.sh | sh
}

install_XMPlus() {
    if [[ -e /usr/local/XMPlus/ ]]; then
        rm /usr/local/XMPlus/ -rf
    fi

    mkdir /usr/local/XMPlus/ -p
	
	cd /usr/local/XMPlus/

    if  [ $# == 0 ] ;then
        last_version=$(curl -Ls "https://api.github.com/repos/XMPlusDev/XMPlus/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
        if [[ ! -n "$last_version" ]]; then
            echo -e "${red}Failed to detect the XMPlus version, it may be because of Github API limit, please try again later, or manually specify the XMPlus version to install${plain}"
            exit 1
        fi
        echo -e "XMPlus latest version detected：${last_version}，Start Installation"
        wget -N --no-check-certificate -O /usr/local/XMPlus/XMPlus-linux.zip https://github.com/XMPlusDev/XMPlus/releases/download/${last_version}/XMPlus-linux-${kernelArch}.zip
        if [[ $? -ne 0 ]]; then
            echo -e "${red}Downloading XMPlus failed，Please make sure your server can download github file${plain}"
            exit 1
        fi
    else
        last_version=$1
        url="https://github.com/XMPlusDev/XMPlus/releases/download/${last_version}/XMPlus-linux-${kernelArch}.zip"
        echo -e "Start Installation XMPlus v$1"
        wget -N --no-check-certificate -O /usr/local/XMPlus/XMPlus-linux.zip ${url}
        if [[ $? -ne 0 ]]; then
            echo -e "${red}Downloading XMPlus v$1 failed, make sure this version exists${plain}"
            exit 1
        fi
    fi

    unzip XMPlus-linux.zip
    rm XMPlus-linux.zip -f
    chmod +x XMPlus
	
    if [ -e "/etc/systemd/system/" ] ; then
		if [ -e "/usr/lib/systemd/system/XMPlus.service" ] ; then
			systemctl stop XMPlus
			systemctl disable XMPlus
		    rm /etc/systemd/system/XMPlus.service -f
		fi
		
		file="https://raw.githubusercontent.com/XMPlusDev/XMPlus/scripts/XMPlus.service"
		wget -N --no-check-certificate -O /etc/systemd/system/XMPlus.service ${file}
		systemctl daemon-reload
		systemctl stop XMPlus
		systemctl enable XMPlus
    elif [ -e "/usr/sbin/rc-service" ] ; then
		if [ -e "/etc/init.d/xmplus" ] ; then
			systemctl stop XMPlus
			systemctl disable XMPlus
			rm /etc/init.d/xmplus/xmplus.rc -f
		else	
			 mkdir /etc/init.d/xmplus/ -p
		fi
		file="https://raw.githubusercontent.com/XMPlusDev/XMPlus/scripts/xmplus.rc"
		wget -N --no-check-certificate -O /etc/init.d/xmplus/xmplus.rc ${file}
		systemctl daemon-reload
		rc-update add xmplus default 
		rc-update --update
		chmod +x /etc/init.d/xmplus/xmplus.rc
		ln -s /etc/XMPlus /usr/local/etc/
    else
       echo "not found."
    fi	
	
    mkdir /etc/XMPlus/ -p
	
    echo -e "${green}XMPlus ${last_version}${plain} The installation is complete，XMPlus has restarted"
	
    cp geoip.dat /etc/XMPlus/
	
    cp geosite.dat /etc/XMPlus/ 
	
    if [[ ! -f /etc/XMPlus/dns.json ]]; then
		cp dns.json /etc/XMPlus/
	fi
	if [[ ! -f /etc/XMPlus/route.json ]]; then 
		cp route.json /etc/XMPlus/
	fi
	
	if [[ ! -f /etc/XMPlus/outbound.json ]]; then
		cp outbound.json /etc/XMPlus/
	fi
	
	if [[ ! -f /etc/XMPlus/inbound.json ]]; then
		cp inbound.json /etc/XMPlus/
	fi

	if [[ ! -f /etc/XMPlus/rulelist ]]; then
		cp rulelist /etc/XMPlus/
	fi
	
    if [[ ! -f /etc/XMPlus/config.yml ]]; then
        cp config.yml /etc/XMPlus/
    else
		if [ -e "/etc/systemd/system/" ] ; then
			systemctl start XMPlus
		else
			rc-service xmplus start
		fi
        sleep 2
        check_status
        echo -e ""
        if [[ $? == 0 ]]; then
            echo -e "${green}XMPlus restart successfully${plain}"
        else
            echo -e "${red} XMPlus May fail to start, please use [ XMPlus log ] View log information ${plain}"
        fi
    fi
    
    curl -o /usr/bin/XMPlus -Ls https://raw.githubusercontent.com/XMPlusDev/XMPlus/scripts/XMPlus.sh
    chmod +x /usr/bin/XMPlus
    ln -s /usr/bin/XMPlus /usr/bin/xmplus 
    chmod +x /usr/bin/xmplus

    echo -e ""
    echo "XMPlus Management usage method: "
    echo "------------------------------------------"
    echo "XMPlus                    - Show menu (more features)"
    echo "XMPlus start              - Start XMPlus"
    echo "XMPlus stop               - Stop XMPlus"
    echo "XMPlus restart            - Restart XMPlus"
    echo "XMPlus status             - View XMPlus status"
    echo "XMPlus enable             - Enable XMPlus auto-start"
    echo "XMPlus disable            - Disable XMPlus auto-start"
    echo "XMPlus log                - View XMPlus logs"
    echo "XMPlus update             - Update XMPlus"
    echo "XMPlus update vx.x.x      - Update XMPlus Specific version"
    echo "XMPlus config             - Show configuration file content"
    echo "XMPlus install            - Install XMPlus"
    echo "XMPlus uninstall          - Uninstall XMPlus"
    echo "XMPlus version            - View XMPlus version"
    echo "XMPlus update_script      - Upgrade script"
    echo "XMPlus warp               - Generate cloudflare warp account"
    echo "XMPlus x25519             - enerate reality key pairs"
    echo "------------------------------------------"
}

echo -e "${green}Start Installation${plain}"
install_base
#install_acme
install_XMPlus $1
