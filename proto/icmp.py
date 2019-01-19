import struct


class ICMP:

    def __init__(self, raw_data):
        # Type - ICMP的类型,标识生成的错误报文
        # Code - 进一步划分ICMP的类型,该字段用来查找产生错误的原因
        # Checksum - 校验码部分,包含用于检查错误的数据
        self.type, self.code, self.checksum = struct.unpack('! B B H', raw_data[:4])
        self.data = raw_data[4:]
