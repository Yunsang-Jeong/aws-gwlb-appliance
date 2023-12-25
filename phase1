import signal
import socket
import select
import struct
import dataclasses
from typing import List, Dict, Callable, Any
from dataclasses import dataclass, field
import logging

LOGGER = logging.getLogger(__name__)

DUMMY_LAMBDA=lambda d: d

class SocketCloser:
  def __init__(self):
    self.close_now = False
    signal.signal(signal.SIGINT, self.set_close_now_flag)
    signal.signal(signal.SIGTERM, self.set_close_now_flag)

  def set_close_now_flag(self, *args):
    self.close_now = True
    print("[*] Success to set close now flag")

@dataclass
class FixedFieldSpec:
    name : str
    unpack_index: int
    unpakcer: Callable[[int], int] = DUMMY_LAMBDA
    packer: Callable[[int], int] = DUMMY_LAMBDA
    pack_with_swap: int = None
    translator: Callable[[int], str] = DUMMY_LAMBDA

@dataclass
class OptionalFieldsSpec:
    fixed_fields_format: str = None
    fixed_fields_specs: List[FixedFieldSpec] = field(default_factory=list)
    remain_field_size_calcurator: Callable[[List], int] = None

@dataclass
class HeaderSpec:
    name: str
    fixed_fields_format: str
    fixed_fields_specs: List[FixedFieldSpec]
    optional_fields_spec: OptionalFieldsSpec
    header_size_calcurator: Callable[[List], int] = None

@dataclass
class FixedField:
    name : str
    field_index: int
    unpack_index: int
    value: int
    easy_value: str

@dataclass
class OptionalFieldsGroup:
    group_index: int
    fields: List[FixedField] = field(default_factory=list)

@dataclass
class Header:
    header_size: int
    fixed_fields_size: int
    fixed_fields_format: str
    fixed_fields: List[FixedField]
    optional_fields_raw: bytes = None
    optional_fields_groups: List[OptionalFieldsGroup] = field(default_factory=list)

PROTOCOL_MAP = {
    "IPv4": HeaderSpec(
        name="IPv4",
        fixed_fields_format="!BBHHHBBH4s4s",
        fixed_fields_specs=[
            ###############################################################
            FixedFieldSpec("version", 0, unpakcer=lambda d: d >> 4, packer=lambda d: d << 4),
            FixedFieldSpec("ihl", 0, unpakcer=lambda d: d & 0xF),
            ###############################################################
            FixedFieldSpec("dscp", 1, unpakcer=lambda d: d >> 2, packer=lambda d: d << 2),
            FixedFieldSpec("ecn", 1, unpakcer=lambda d: d & 0x3),
            ###############################################################
            FixedFieldSpec("total_length", 2),
            ###############################################################
            FixedFieldSpec("id", 3),
            ###############################################################
            FixedFieldSpec("flag_x", 4, unpakcer=lambda d: d >> 15 & 1, packer=lambda d: d << 15),
            FixedFieldSpec("flag_d", 4, unpakcer=lambda d: d >> 14 & 1, packer=lambda d: d << 14),
            FixedFieldSpec("flag_m", 4, unpakcer=lambda d: d >> 13 & 1, packer=lambda d: d << 13),
            FixedFieldSpec("frag_offset", 4, unpakcer=lambda d: d & 0x2000),
            ###############################################################
            FixedFieldSpec("ttl", 5),
            ###############################################################
            FixedFieldSpec("protocol", 6),
            ###############################################################
            FixedFieldSpec("checksum", 7, packer=lambda d: 0),
            ###############################################################
            FixedFieldSpec("src_addr", 8, pack_with_swap=14, translator=lambda d: socket.inet_ntoa(d)),
            ###############################################################
            FixedFieldSpec("dst_addr", 9, pack_with_swap=13, translator=lambda d: socket.inet_ntoa(d)),
            ###############################################################
        ],
        header_size_calcurator=lambda d : d[1].value * 4,
        optional_fields_spec=OptionalFieldsSpec(),
    ),
    "TCP": HeaderSpec(
        name="TCP",
        fixed_fields_format="!HHIIHHHH",
        fixed_fields_specs=[
            ###############################################################
            FixedFieldSpec("src_port", 0),
            ###############################################################
            FixedFieldSpec("dst_port", 1),
            ###############################################################
            FixedFieldSpec("seq", 2),
            ###############################################################
            FixedFieldSpec("ack", 3),
            ###############################################################
            FixedFieldSpec("offset", 4, unpakcer=lambda d: d >> 12),
            FixedFieldSpec("urg", 4, unpakcer=lambda d: d >> 5 & 0x1),
            FixedFieldSpec("ack", 4, unpakcer=lambda d: d >> 4 & 0x1),
            FixedFieldSpec("psh", 4, unpakcer=lambda d: d >> 3 & 0x1),
            FixedFieldSpec("rst", 4, unpakcer=lambda d: d >> 2 & 0x1),
            FixedFieldSpec("syn", 4, unpakcer=lambda d: d >> 1 & 0x1),
            FixedFieldSpec("fin", 4, unpakcer=lambda d: d & 0x1),
            ###############################################################
            FixedFieldSpec("window", 5),
            ###############################################################
            FixedFieldSpec("checksum", 6),
            ###############################################################
            FixedFieldSpec("urg_pointer", 7),
            ###############################################################
        ],
        header_size_calcurator=lambda d : (d[4].value - 5) * 4,
        optional_fields_spec=OptionalFieldsSpec(),
    ),
    "UDP": HeaderSpec(
        name="UDP",
        fixed_fields_format="!HHHH",
        fixed_fields_specs=[
            ###############################################################
            FixedFieldSpec("src_port", 0, pack_with_swap=1),
            ###############################################################
            FixedFieldSpec("dst_port", 1, pack_with_swap=0),
            ###############################################################
            FixedFieldSpec("length", 2),
            ###############################################################
            FixedFieldSpec("checksum", 3),
            ###############################################################
        ],
        optional_fields_spec=OptionalFieldsSpec(),
    ),
    "Geneve": HeaderSpec(
        name="Geneve",
        fixed_fields_format="!BBH3sB",
        fixed_fields_specs=[
            ###############################################################
            FixedFieldSpec("version", 0, unpakcer=lambda d: d >> 6),
            FixedFieldSpec("options_length", 0, unpakcer=lambda d: d & 0x3F),
            ###############################################################
            FixedFieldSpec("control", 1, unpakcer=lambda d: d >> 7),
            FixedFieldSpec("critical", 1, unpakcer=lambda d: d >> 6 & 0x1),
            ###############################################################
            FixedFieldSpec("protocol", 2),
            ###############################################################
            FixedFieldSpec("vni", 3),
            ###############################################################
            FixedFieldSpec("reserved", 4),
            ###############################################################
        ],
        header_size_calcurator=lambda d : 8 + d[1].value * 4,
        optional_fields_spec=OptionalFieldsSpec(
            fixed_fields_format="!HBB",
            fixed_fields_specs = [
                ###############################################################
                FixedFieldSpec("option_class", 0),
                ###############################################################
                FixedFieldSpec("option_type", 1),
                FixedFieldSpec("critical", 1, unpakcer=lambda d: d >> 7),
                ###############################################################
                FixedFieldSpec("option_length", 2, unpakcer=lambda d: d & 0x1F),
                ###############################################################
            ],
            remain_field_size_calcurator=lambda d: d[3].value * 4,
        ),
    ),
}

class SocketProxy:
    def __init__(self, protocol_header_spec_map: Dict[str, HeaderSpec], logger: logging.Logger) -> None:
        self.protocol_header_spec_map = protocol_header_spec_map
        self.logger = logger
        
    def run(self, protocol_orders: List[str], raw_data: bytes, dry_run=False) -> (Dict[str, Header], bytearray, int):
        raw_data_pointer = 0

        unpacked_headers = {}
        repacked_headers = bytearray()
        for proto in protocol_orders:
            spec = self.protocol_header_spec_map.get(proto)
            #
            # Unpack
            #
            unpacked_header = self.unpack_header(spec, raw_data, raw_data_pointer)
            unpacked_headers[proto] = unpacked_header
            #
            # Add pointer
            #
            raw_data_pointer += unpacked_header.header_size
            #
            # Re-pack with swap
            #
            if dry_run:
                continue
            
            repacked_protocol_header = self.repack_with_swap(spec, unpacked_header)
            repacked_headers += repacked_protocol_header
        
        return unpacked_headers, repacked_headers, raw_data_pointer

    def unpack_header(self, spec: HeaderSpec, raw_data: bytes, raw_data_pointer: int) -> Header:
        #
        # fixed-field의 크기를 계산하고, raw_data를 자릅니다.
        #
        fixed_fields_size = struct.calcsize(spec.fixed_fields_format)
        fixed_fields_raw = raw_data[raw_data_pointer : raw_data_pointer + fixed_fields_size]
        #
        # fixed-field를 추출합니다.
        #
        unpacked_fixed_fields = struct.unpack(spec.fixed_fields_format, fixed_fields_raw)
        #
        # 추출한 fixed-field를 spec에 맞춰 분할합니다.
        # 이 때, struct.unapck 최소단위가 Byte이므로, bit단위 연산이 필요한 경우 unpakcer로 연산을 진행합니다.
        #
        fixed_fields = []
        for field_index, field_spec in enumerate(spec.fixed_fields_specs):
            value = field_spec.unpakcer(unpacked_fixed_fields[field_spec.unpack_index])
            
            fixed_fields.append(
                FixedField(
                    name=field_spec.name, 
                    field_index=field_index,
                    unpack_index=field_spec.unpack_index,
                    value=value, 
                    easy_value=field_spec.translator(value) if field_spec.translator is not None else value
                )
            )
        #
        # 전체 Header 크기를 계산와, 전체 optional-field의 크기를 계산
        #
        header_size = fixed_fields_size
        if spec.header_size_calcurator is not None:
            header_size = spec.header_size_calcurator(fixed_fields)

        opt_fields_size = header_size - fixed_fields_size
        
        #
        # optional-field 가 없다면 리턴
        #
        if opt_fields_size == 0:
            return Header(
                header_size=fixed_fields_size,
                fixed_fields_size=fixed_fields_size,
                fixed_fields_format=spec.fixed_fields_format,
                fixed_fields=fixed_fields,
            )
        #
        # optional-field를 추출합니다.
        #
        opt_spec = spec.optional_fields_spec
        opt_fields_groups = []
        opt_fields_start = raw_data_pointer + fixed_fields_size
        opt_fields_raw = raw_data[opt_fields_start : opt_fields_start + opt_fields_size]
        
        # print(fixed_fields)

        # if opt_spec is None:
        #     print(f"[E] spec.name: {spec.name}")

        #     print(f"[E] fixed_fields_size: {fixed_fields_size}")
        #     print(f"[E] fixed_fields_raw: {fixed_fields_raw}")
        #     print(f"[E] fixed_fields: {fixed_fields}")

        #     print(f"[E] opt_fields_size: {opt_fields_size}")
        #     print(f"[E] opt_fields_raw: {opt_fields_raw}")

        #     raise Exception(f"need optional_fields_spec in {spec.name}.")

        if opt_spec.fixed_fields_format is None or opt_spec.fixed_fields_specs is None:
            #
            # optional-field에 대한 포맷과 스펙이 정의되지 않은 경우 하나의 field로 추출합니다.
            #
            group = OptionalFieldsGroup(group_index=0)
            group.fields.append(
                FixedField(
                    name=f"-",
                    field_index=0,
                    unpack_index=0,
                    value=opt_fields_raw,
                    easy_value=opt_fields_raw,
            ))
            opt_fields_groups.append(group)
        else:
            #
            # optional-field에 대한 포맷과 스펙에 따라 추출합니다.
            #
            pointer = 0
            group_count = 0
            fixed_fields_format = opt_spec.fixed_fields_format
            fixed_group_size = struct.calcsize(fixed_fields_format)
            while pointer < opt_fields_size:
                unpacked = struct.unpack(
                    fixed_fields_format, 
                    opt_fields_raw[pointer : pointer + fixed_group_size]
                )
                group = OptionalFieldsGroup(group_index=group_count)

                for field_index, field_spec in enumerate(opt_spec.fixed_fields_specs):
                    value = field_spec.unpakcer(unpacked[field_spec.unpack_index])

                    group.fields.append(
                        FixedField(
                            name=field_spec.name,
                            field_index=field_index,
                            unpack_index=field_spec.unpack_index,
                            value=value,
                            easy_value=value,
                        )
                    )
                
                remain_field_size = opt_spec.remain_field_size_calcurator(group.fields)                
                if remain_field_size > 0:
                    value = opt_fields_raw[pointer + fixed_group_size : pointer + fixed_group_size + remain_field_size]

                    group.fields.append(
                        FixedField(
                            name=f"-",
                            field_index=len(group.fields),
                            unpack_index=len(group.fields),
                            value=value,
                            easy_value=value,
                        )
                    )

                group_count += 1
                pointer += fixed_group_size + remain_field_size
                opt_fields_groups.append(group)


        return Header(
                header_size=header_size,
                fixed_fields_size=fixed_fields_size,
                fixed_fields_format=spec.fixed_fields_format,
                fixed_fields=fixed_fields,
                optional_fields_raw=opt_fields_raw,
                optional_fields_groups=opt_fields_groups,
            )
    
    def repack_with_swap(self, spec: HeaderSpec, unpacked_protocol_header: Header) -> bytearray:
        fixed_fileds = unpacked_protocol_header.fixed_fields

        assembled = []

        for i, s in enumerate(spec.fixed_fields_specs):
            value = fixed_fileds[i].value
            #
            # SWAP이 필요한 경우
            #
            if s.pack_with_swap is not None:
                value = fixed_fileds[s.pack_with_swap].value
            #
            # Packer 실행
            #
            value = s.packer(value)
            #
            # 기존의 Header 구성에 맞게 값을 주입합니다.
            #
            if type(value) is bytes:
                if len(assembled) <= fixed_fileds[i].unpack_index:
                    assembled.append(b'0')

                assembled[fixed_fileds[i].unpack_index] = value
            else:
                if len(assembled) <= fixed_fileds[i].unpack_index:
                    assembled.append(0)

                assembled[fixed_fileds[i].unpack_index] += value
    
        buffer = bytearray(unpacked_protocol_header.header_size)
        struct.pack_into(unpacked_protocol_header.fixed_fields_format, buffer, 0, *assembled)
        
        if unpacked_protocol_header.optional_fields_raw is not None:
            buffer += unpacked_protocol_header.optional_fields_raw
        
        return buffer


closer = SocketCloser()
proxy = SocketProxy(PROTOCOL_MAP, LOGGER)

geneve_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
geneve_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcp_socket.bind(('0.0.0.0', 80))
tcp_socket.listen()

sockets = [geneve_socket, tcp_socket]

while not closer.close_now:
    rs, _, _ = select.select(sockets, [], [], 3)
    for s in rs:
        if s == tcp_socket:
            cs, addr = s.accept()
            cs.recv(0)
            cs.close()
        elif s == geneve_socket:
            raw_data, addr = s.recvfrom(65536)

            outter_unpacked, outter_repacked, outter_payloadpoint = proxy.run(["IPv4", "UDP"], raw_data)
            outter_src_ip = outter_unpacked["IPv4"].fixed_fields[13].easy_value
            outter_dst_ip = outter_unpacked["IPv4"].fixed_fields[14].easy_value
            outter_src_port = outter_unpacked["UDP"].fixed_fields[0].easy_value
            outter_dst_port = outter_unpacked["UDP"].fixed_fields[1].easy_value

            print(f"[RECV]")
            print(f" - [OUT] info  : UDP {outter_src_ip}:{outter_src_port} -> {outter_dst_ip}:{outter_dst_port}")

            if outter_dst_port == 6081:
                geneve_startpoint = outter_payloadpoint
                geneve, _, geneve_payloadpoint = proxy.run(["Geneve"], raw_data[geneve_startpoint:], True)
                for group in geneve["Geneve"].optional_fields_groups:
                    print(" ".join([
                        f"   - geneveoption/{group.group_index}:",
                        f"class: {group.fields[0].easy_value},",
                        f"type: {group.fields[1].easy_value},",
                        f"value: {group.fields[-1].easy_value},",
                    ]))

                inner_ipv4_startpoint = geneve_startpoint + geneve_payloadpoint
                inner_ipv4_unpacked, _, inner_ipv4_payloadpoint = proxy.run(["IPv4"], raw_data[inner_ipv4_startpoint:], True)
                inner_protocol = inner_ipv4_unpacked["IPv4"].fixed_fields[11].easy_value
                inner_src_ip = inner_ipv4_unpacked["IPv4"].fixed_fields[13].easy_value
                inner_dst_ip = inner_ipv4_unpacked["IPv4"].fixed_fields[14].easy_value

                if inner_protocol == 6:
                    #
                    # TCP
                    #
                    inner_tcp_startpoint = inner_ipv4_startpoint + inner_ipv4_payloadpoint
                    inner_tcp_unpacked, _, inner_tcp_payloadpoint = proxy.run(["TCP"], raw_data[inner_tcp_startpoint:], True)
                    inner_src_port = inner_tcp_unpacked["TCP"].fixed_fields[0].easy_value
                    inner_dst_port = inner_tcp_unpacked["TCP"].fixed_fields[1].easy_value
                    print(f" - [IN] info   : TCP {inner_src_ip}:{inner_src_port} -> {inner_dst_ip}:{inner_dst_port}")
                    print(f" - [IN] payload: {raw_data[inner_tcp_startpoint + inner_tcp_payloadpoint:]}")
                    print(f" - [IN] options: {inner_tcp_unpacked['TCP'].optional_fields_raw}")
                    
                elif inner_protocol == 17:
                    #
                    # UDP
                    #
                    inner_udp_startpoint = inner_ipv4_startpoint + inner_ipv4_payloadpoint
                    inner_udp_unpacked, _, inner_udp_pp = proxy.run(["UDP"], raw_data[inner_udp_startpoint:], True)
                    inner_src_port = inner_udp_unpacked["UDP"].fixed_fields[0].easy_value
                    inner_dst_port = inner_udp_unpacked["UDP"].fixed_fields[1].easy_value
                    print(f" - [IN] info   : UDP {inner_src_ip}:{inner_src_port} -> {inner_dst_ip}:{inner_dst_port}")
                    print(f" - [IN] payload: {raw_data[inner_udp_startpoint + inner_udp_pp:]}")
                else:
                    print(f"[-] inner-packet is not supported protocol: {inner_protocol}")
                
            else:    
                print(f" - payload: {raw_data[outter_payloadpoint:70]}...")

            s.sendto(outter_repacked + raw_data[outter_payloadpoint:], (addr[0], outter_src_port))

            print(f"[RESP] reply to {addr[0]}:{outter_src_port}")
            print("-"*64)

for s in sockets:
    s.close()
