FROM ubuntu:18.04

# This installs princpal net tools,
# and installs open ssh v7.6 - sus: CVE-2018-15473
RUN apt update \
    && apt install -y nano \
    && apt install -y iproute2 iputils-ping net-tools openvswitch-switch openvpn bridge-utils ebtables vlan tcpdump \
    && apt install -y openssh-server \
    && mkdir /var/run/sshd \