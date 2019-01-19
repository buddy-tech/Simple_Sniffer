#!/usr/bin/env python3

import socket
import fcntl
import ctypes
import argparse
from termcolor import *

from proto.ethernet import Ethernet
from proto.ipv4 import IPv4
from proto.icmp import ICMP
from proto.tcp import TCP
from proto.udp import UDP
from proto.http import HTTP

PROTOCOL = ('ETHERNET', 'ARP', 'IPV4', 'TCP', 'UDP', 'ICMP', 'DNS', 'HTTP')
PROTO_NUM = {'IPV4': 8, 'ICMP': 1, 'TCP': 6}


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

    if proto not in PROTOCOL and proto != 'ALL':
        raise ProtocolException

    eth = Ethernet(raw_data)
    if proto == 'ETHERNET' or proto == 'ALL':
        print(colored('Ethernet Frame:', 'red'))
        print(f'Destination: {eth.dest_mac}, Source: {eth.src_mac}, Protocol: {eth.proto}')
        success = True

    if eth.proto == PROTO_NUM['IPV4']:
        ipv4 = IPv4(eth.data)
        if proto == 'IPV4' or proto == 'ALL':
            print('IPv4 Packet:')
            print(f'Version: {ipv4.version}, Header Length: {ipv4.header_length}, TTL: {ipv4.ttl}')
            print(f'Source: {ipv4.src}, Target: {ipv4.target}')
            success = True

        if ipv4.proto == PROTO_NUM['ICMP']:
            icmp = ICMP(ipv4.data)
            if proto == 'ICMP' or proto == 'ALL':
                print('ICMP Packet:')
                print(f'Type: {icmp.type}, Code: {icmp.coded}, Checksum: {icmp.checksum}')
                print(f'ICMP Data: {icmp.data}')
                success = True

        elif ipv4.proto == PROTO_NUM['TCP']:
            tcp = TCP(ipv4.data)
            if proto == 'TCP' or proto == 'ALL':
                print('TCP Segment:')
                print(f'Source Port: {tcp.src_port}, Destination Port: {tcp.dest_port}')
                print(f'Sequence: {tcp.sequence}, Acknowledgment: {tcp.acknowledgment}')
                success = True

    return success


def sniff(count, proto, promisc):
    """创建socket对象"""

    try:
        if promisc:
            with PromiscuousSocket() as conn:

                packet_number = 1
                while packet_number <= count:
                    raw_data, addr = conn.recvfrom(65535)
                    print('-' * 10, '\nPacket Id:', packet_number)
                    if _filter_and_show(raw_data, proto):
                        packet_number += 1
        else:
            conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            packet_number = 1

            while packet_number <= count:
                raw_data, addr = conn.recvfrom(65535)
                print('-' * 10, '\nPacket Id:', packet_number)
                if _filter_and_show(raw_data, proto):
                    packet_number += 1

            conn.close()
    except PermissionError as err:
        print("Must sudo!!!")


class ProtocolException(Exception):
    """When input a protocol which dosen't support"""
    pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-n', '--number', type=int, help="pakcet's number of output")
    parser.add_argument('-p', '--protocol', type=str, help='output specific protocol')
    parser.add_argument('-P', '--promisc', action='store_true', help='promic mode')
    args = parser.parse_args()

    num = args.number or 30
    proto = args.protocol or 'ALL'
    promisc = args.promisc

    sniff(num, proto, promisc)
