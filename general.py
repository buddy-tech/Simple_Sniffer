import textwrap


# Returns MAC as string from bytes (ie AA:BB:CC:DD:EE:FF)
def get_mac_addr(mac_raw):
    # 数字格式化
    byte_str = map('{:02x}'.format, mac_raw)
    mac_addr = ':'.join(byte_str).upper()
    return mac_addr


# Formats multi-line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        # 如果数据是bytes类型
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


def asciiDump(data):
    output = '  '
    for x in data:
        if x in range(32, 127):
            output += chr(x)
        else:
            output += '.'
    output += '\n'
    return output


def dump(data):
    output = '--- DATA DUMP ---\n'
    output += 'Offset(h)  '
    for i in range(16):
        output += ('%02X ' % i)
    output += '\tASCII\n'
    line = 0  # every line holds 16 bytes
    index = 0  # index of the current line in data
    for i in range(len(data)):
        if i % 16 == 0:
            output += asciiDump(data[index:i])
            index = i
            # print the new line address
            output += ('%08X   ' % line)
            line += 1
        output += ('%02X ' % data[i])
    return output
