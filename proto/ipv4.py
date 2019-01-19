import struct


class IPv4:

    def __init__(self, raw_data):
        # 版本和头部长度共一个字节
        version_header_length = raw_data[0]
        self.version = version_header_length >> 4
        self.header_length = (version_header_length & 15) * 4
        # x为填充字节，为了对齐(不进行转换）
        # 8x填充版本、头长度、服务类型和总长度
        # 2x填充首部检验和
        self.ttl, self.proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
        self.src = self.ipv4(src)
        self.target = self.ipv4(target)
        self.data = raw_data[self.header_length:]

    # Returns properly formatted IPv4 address
    def ipv4(self, addr):
        return '.'.join(map(str, addr))
