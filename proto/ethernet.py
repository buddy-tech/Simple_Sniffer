import socket
import struct
from general import *


class Ethernet:

    def __init__(self, raw_data):
        # 获取前14个字节
        # 目标MAC：6 bytes
        # 源MAC：6 bytes
        # 以太类型：2 bytes
        # IPv4的以太类型编号：0x0800
        dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])

        self.dest_mac = get_mac_addr(dest)
        self.src_mac = get_mac_addr(src)
        # 把16位正整数从主机字节序转换成网络序
        self.proto = socket.htons(prototype)
        self.data = raw_data[14:]
