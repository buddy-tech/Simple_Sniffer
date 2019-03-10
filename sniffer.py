#!/usr/bin/env python3

import socket
import fcntl
import ctypes
import argparse

from proto.ethernet import Ethernet
from proto.ipv4 import IPv4
from proto.icmp import ICMP
from proto.tcp import TCP
from proto.udp import UDP
from proto.http import HTTP

PROTOCOL = ('ETHERNET', 'ARP', 'IPV4', 'TCP', 'UDP', 'ICMP', 'DNS', 'HTTP')  # 支持的协议类型
PROTO_NUM = {'IPV4': 8, 'ICMP': 1, 'TCP': 6, 'UDP': 17}  # 协议号


class FLAGS:
    SIOCGIFFLAGS = 0x8913
    SIOCSIFFLAGS = 0x8914
    IFF_PROMISC = 0x100
    ETH_P_ALL = 0x0003


class ifreq(ctypes.Structure):
    _fields_ = [('ifr_ifrn', ctypes.c_char * 16), ('ifr_flags', ctypes.c_short)]


class PromiscuousSocket:
    """创建socket对象并打开混杂模式"""

    def __init__(self):
        # ntohs将16位正整数从网络序转换成主机字节序
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(FLAGS.ETH_P_ALL))
        # 开启混杂模式
        try:
            ifr = ifreq()
            ifr.ifr_ifrn = b'eth0'
            fcntl.ioctl(s, FLAGS.SIOCGIFFLAGS, ifr)
            ifr.ifr_flags |= FLAGS.IFF_PROMISC
            fcntl.ioctl(s, FLAGS.SIOCSIFFLAGS, ifr)
        except Exception as why:
            print('Error:', str(why))
        self.ifr = ifr
        self.s = s

    def __enter__(self):
        return self.s

    def __exit__(self, *args, **kwargs):
        self.ifr.ifr_flags ^= FLAGS.IFF_PROMISC  # mask it off (remove)
        fcntl.ioctl(self.s, FLAGS.SIOCSIFFLAGS, self.ifr)  # update


def _filter_and_show(raw_data, proto):
    proto = proto.upper()
    success = False
    output = ''

    if proto not in PROTOCOL and proto != 'ALL':
        raise ProtocolException

    eth = Ethernet(raw_data)
    if proto == 'ETHERNET' or proto == 'ALL':
        output = output \
                 + 'Ethernet Frame:\n' \
                 + f'Destination: {eth.dest_mac}, Source: {eth.src_mac}, Protocol: {eth.proto}\n'
        success = True

    if eth.proto == PROTO_NUM['IPV4']:
        ipv4 = IPv4(eth.data)
        if proto == 'IPV4' or proto == 'ALL':
            output += 'IPv4 Packet:\n' \
                      + f'Version: {ipv4.version}, Header Length: {ipv4.header_length}, TTL: {ipv4.ttl}\n' \
                      + 'Source: {ipv4.src}, Target: {ipv4.target}\n'
            success = True

        if ipv4.proto == PROTO_NUM['ICMP']:
            icmp = ICMP(ipv4.data)
            if proto == 'ICMP' or proto == 'ALL':
                output += 'ICMP Packet:\n' \
                          + f'Type: {icmp.type}, Code: {icmp.coded}, Checksum: {icmp.checksum}\n' \
                          + f'ICMP Data: {icmp.data}\n'
                success = True

        elif ipv4.proto == PROTO_NUM['UDP']:
            udp = UDP(ipv4.data)
            if proto == 'UDP' or proto == 'ALL':
                output = f'UDP Segment:\n' \
                         + f'Source Port: {udp.src_port}, Destination Port: {udp.dest_port}\n' \
                         + f'Packet Length: {udp.size}'
                success = True

        elif ipv4.proto == PROTO_NUM['TCP']:
            tcp = TCP(ipv4.data)
            if proto == 'TCP' or proto == 'ALL':
                output = 'TCP Segment:\n' \
                         + f'Source Port: {tcp.src_port}, Destination Port: {tcp.dest_port}' \
                         + f'Sequence: {tcp.sequence}, Acknowledgment: {tcp.acknowledgment}'
                success = True

            if tcp.src_port == 80 or tcp.dest_port == 80:
                if proto == 'HTTP' or proto == 'ALL':
                    http = HTTP(tcp.data)
                    output = 'HTTP Segment:\n' \
                             + http.data if len(http.data) > 0 else '(Empty packet)'
                    success = True

    return (success, output)


def sniff(count, proto, promisc):
    """创建socket对象"""

    try:
        if promisc:
            conn = PromiscuousSocket().s
        else:
            conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

        packet_number = 1
        while packet_number <= count:
            raw_data, addr = conn.recvfrom(65535)
            success, output = _filter_and_show(raw_data, proto)
            if success:
                print('-' * 10, '\nPacket Id:', packet_number)
                print(output)
                packet_number += 1
        conn.close()
    except PermissionError as err:
        print("[-] Must sudo.")
    except KeyboardInterrupt as err:
        print("\n[-] Keyboard Interrupt! Exit!")


class ProtocolException(Exception):
    """When input a protocol which dosen't support"""
    pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-n', '--number', type=int, help="pakcet's number of output")
    parser.add_argument('-p', '--protocol', type=str, help='output specific protocol')
    parser.add_argument('-P', '--promisc', action='store_true', help='promisc mode')
    args = parser.parse_args()

    num = args.number or 30
    proto = args.protocol or 'ALL'
    promisc = args.promisc

    sniff(num, proto, promisc)
