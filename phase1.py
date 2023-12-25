import os
import sys
import copy
import signal
import socket
import select
import struct


class SocketCloser:
  def __init__(self):
    self.close_now = False
    signal.signal(signal.SIGINT, self.set_close_now_flag)
    signal.signal(signal.SIGTERM, self.set_close_now_flag)

  def set_close_now_flag(self, *args):
    self.close_now = True
    print("[*] Success to set close now flag")

class IPv4:
    HEADER_FMT='!BBHHHBBH4s4s'

    def __init__(self, raw_packet: bytes):
        self.header_size_without_options = struct.calcsize(self.HEADER_FMT)
        self.header_without_options = bytearray(raw_packet[:self.header_size_without_options])
        self.checksum_result = self.calcurate_checksum(self.header_without_options)
    
        unpacked = struct.unpack(self.HEADER_FMT, self.header_without_options)
        self.version = unpacked[0] >> 4
        self.ihl = unpacked[0] & 0xF
        self.tos = unpacked[1]
        self.tlen = unpacked[2]
        self.id = unpacked[3]
        self.frag_off = unpacked[4]
        self.ttl = unpacked[5]
        self.proto = unpacked[6]
        self.checksum = unpacked[7]
        self.src_addr = unpacked[8]
        self.dst_addr = unpacked[9]
        self.options = b''

        self.header_size = self.ihl * 4
        if self.header_size > 20:
            self.options = raw_packet[20:(self.ihl - 5) * 4]

        self.header = self.header_without_options + self.options

    def __repr__(self):
        return "[IPv4] {src_addr} -> {dst_addr}".format_map({
            "src_addr" : socket.inet_ntoa(self.src_addr),
            "dst_addr" : socket.inet_ntoa(self.dst_addr),
        })

    def calcurate_checksum(self, target: bytearray) -> int:
        checksum = 0
        for index, byte in enumerate(target):
            if index & 1:
                checksum += int(byte)
            else:
                checksum += int(byte) << 8

        return ((checksum & 0xffff) + (checksum >> 16))

    def generte_response_header(self) -> bytearray:
        header = copy.deepcopy(self.header_without_options)
        header[8] = header[8] - 1
        header[12:16], header[16:20] = header[16:20], header[12:16]
        checksum = self.calcurate_checksum(header[:10]+header[12:])
        header[10:12] = ((~checksum) & 0xffff).to_bytes(2, byteorder='big')
        
        return header
        
class TCP:
    HEADER_FMT='!HHIIHHHH'

    def __init__(self, raw_packet: bytes):
        self.header_size_without_options = struct.calcsize(self.HEADER_FMT)
        self.header_without_options = bytearray(raw_packet[:self.header_size_without_options])
    
        unpacked = struct.unpack(self.HEADER_FMT, self.header_without_options)
        self.src_port = unpacked[0]
        self.dst_port = unpacked[1]
        self.seq_num = unpacked[2]
        self.ack_num = unpacked[3]
        self.data_offset = unpacked[4] >> 12
        self.urg = unpacked[4] >> 5 & 0x1
        self.ack = unpacked[4] >> 4 & 0x1
        self.psh = unpacked[4] >> 3 & 0x1
        self.rst = unpacked[4] >> 2 & 0x1
        self.syn = unpacked[4] >> 1 & 0x1
        self.fin = unpacked[4] & 0x1
        self.window = unpacked[5]
        self.checksum = unpacked[6]
        self.urg_pointer = unpacked[7]
        self.options = b''

        self.header_size = (self.data_offset - 5) * 4
        if self.data_offset > 5:
            self.options = unpacked[self.header_size_without_options:self.header_size]

    def __repr__(self):
        return "[TCP] {src_port} -> {dst_port} [flags: {flags}]".format_map({
            "src_port" : self.src_port,
            "dst_port" : self.dst_port,
            "flags" : ", ".join(
                ["URG"] if self.syn == 1 else [] +
                ["ACK"] if self.ack == 1 else [] +
                ["PSH"] if self.psh == 1 else [] +
                ["RST"] if self.rst == 1 else [] +
                ["SYN"] if self.syn == 1 else [] +
                ["FIN"] if self.fin == 1 else []
            ),
        })


class UDP:
    HEADER_FMT='!HHHH'

    def __init__(self, raw_packet: bytes):
        self.header_size = struct.calcsize(self.HEADER_FMT)
        self.header = bytearray(raw_packet[:self.header_size])
    
        unpacked = struct.unpack(self.HEADER_FMT, self.header)
        self.src_port = unpacked[0]
        self.dst_port = unpacked[1]
        self.length = unpacked[2]
        self.checksum = unpacked[3]

    def __repr__(self):
        return "[UDP] {src_port} -> {dst_port}".format_map({
            "src_port" : self.src_port,
            "dst_port" : self.dst_port,
        })

    def generte_response_header(self) -> bytearray:
        header = copy.deepcopy(self.header)
        header[0:2], header[2:4] = self.header[2:4], self.header[2:4]

        return header

class Geneve:
    HEADER_FMT='!BBH3sB'

    def __init__(self, raw_packet: bytes):
        self.header_size_without_options = struct.calcsize(self.HEADER_FMT)
        self.header_without_options = bytearray(raw_packet[:self.header_size_without_options])
    
        unpacked = struct.unpack(self.HEADER_FMT, self.header_without_options)
        self.version = unpacked[0] >> 6
        self.options_length = unpacked[0] & 0x3F
        self.control = unpacked[1] >> 7
        self.critical = unpacked[1] >> 6 & 0x1
        self.protocol = unpacked[2]
        self.vni = unpacked[3]

        self.header_size = self.header_size_without_options + self.options_length * 4

        option_index = 0
        self.options = []
        while option_index < self.options_length * 4:
            self.options.append(GeneveOption(raw_packet[self.header_size_without_options + option_index:]))
            option_index += self.options[-1].header_size

    def __repr__(self):
        return '[Geneve]\n' +  '\n'.join([
            f' - version: {self.version}',
            f' - options_length: {self.options_length}',
            f' - control: {self.control}',
            f' - critical: {self.critical}',
            f' - protocol: {self.protocol}',
            f' - vni: {self.vni}',
        ] + [
            str(option) for option in self.options
        ])

class GeneveOption:
    HEADER_FMT='!HBB'

    def __init__(self, raw_packet: bytes):
        self.header_size_without_options = struct.calcsize(self.HEADER_FMT)
        self.header_without_options = bytearray(raw_packet[:self.header_size_without_options])
    
        unpacked = struct.unpack(self.HEADER_FMT, self.header_without_options)
        self.option_class = unpacked[0]
        self.option_type = unpacked[1]
        self.critical = unpacked[1] >> 7
        self.option_length = unpacked[2] & 0x1F
        
        self.header_size = self.header_size_without_options + self.option_length * 4
        self.option = raw_packet[self.header_size_without_options:self.header_size]

    def __repr__(self):
        return ' [GeneveOption]\n' +  '\n'.join([
            f'  - option_class: {hex(self.option_class)}',
            f'  - option_type: {hex(self.option_type)}',
            f'  - critical: {self.critical}',
            f'  - option_length: {self.option_length}',
            f'  - option: {self.option.hex()}',
        ])


if not os.environ.get("SUDO_UID") and os.geteuid() != 0:
    sys.exit('Please start with root permissions')

socket_closer = SocketCloser()

geneve_socket= socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
geneve_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
geneve_socket.bind(('0.0.0.0', 0))

health_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
health_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
health_socket.bind(('0.0.0.0', 80))
health_socket.listen()

sockets = [geneve_socket, health_socket]

while not socket_closer.close_now:
    rs, _, _ = select.select(sockets, [], [], 3)
    for s in rs:
        if s == health_socket:
            cs, addr = s.accept()
            cs.recv(0)
            cs.close()
        elif s == geneve_socket and s.proto == 17: # 17 is UDP
            data, addr = s.recvfrom(65536)
            ipv4 = IPv4(data)
            udp = UDP(data[ipv4.header_size:])
            if udp.dst_port != 6081:
                continue
            geneve = Geneve(data[ipv4.header_size+udp.header_size:])

            inner_ipv4 = IPv4(data[ipv4.header_size+udp.header_size+geneve.header_size:])
            inner_tcp = TCP(data[ipv4.header_size+udp.header_size+geneve.header_size+inner_ipv4.header_size:])
            inner_payload = data[ipv4.header_size+udp.header_size+geneve.header_size+inner_ipv4.header_size+inner_tcp.header_size:]

            print('-[OUTER]-----')
            print(ipv4)
            print(udp)
            print(geneve)
            print('-[INNER]-----')
            print(inner_ipv4)
            print(inner_tcp)
            print(inner_payload)
            print('-------------')

            resp = ipv4.generte_response_header() + data[ipv4.header_size:]            
            s.sendto(resp, (addr[0], 6081))

for s in sockets:
    s.close()
