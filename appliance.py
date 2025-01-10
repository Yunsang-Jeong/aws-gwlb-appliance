import signal
import socket
import select
import struct
from typing import List, Dict, Callable, Tuple
from dataclasses import dataclass, field
import logging

LOGGER = logging.getLogger(__name__)

DUMMY_LAMBDA = lambda d: d


class LoopCloser:
    def __init__(self):
        self.close_now = False
        signal.signal(signal.SIGINT, self.set_close_now_flag)
        signal.signal(signal.SIGTERM, self.set_close_now_flag)

    def set_close_now_flag(self, *args):
        self.close_now = True
        print("[*] Success to escape loop")


@dataclass
class FixedFieldSpec:
    name: str
    unpack_index: int
    unpakcer: Callable[[int], int] = DUMMY_LAMBDA
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
    name: str
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
            FixedFieldSpec("version", 0, unpakcer=lambda d: d >> 4),
            FixedFieldSpec("ihl", 0, unpakcer=lambda d: d & 0xF),
            ###############################################################
            FixedFieldSpec("dscp", 1, unpakcer=lambda d: d >> 2),
            FixedFieldSpec("ecn", 1, unpakcer=lambda d: d & 0x3),
            ###############################################################
            FixedFieldSpec("total_length", 2),
            ###############################################################
            FixedFieldSpec("id", 3),
            ###############################################################
            FixedFieldSpec("flag_x", 4, unpakcer=lambda d: d >> 15 & 1),
            FixedFieldSpec("flag_d", 4, unpakcer=lambda d: d >> 14 & 1),
            FixedFieldSpec("flag_m", 4, unpakcer=lambda d: d >> 13 & 1),
            FixedFieldSpec("frag_offset", 4, unpakcer=lambda d: d & 0x2000),
            ###############################################################
            FixedFieldSpec("ttl", 5),
            ###############################################################
            FixedFieldSpec("protocol", 6),
            ###############################################################
            FixedFieldSpec("checksum", 7),
            ###############################################################
            FixedFieldSpec(
                "src_addr",
                8,
                translator=lambda d: socket.inet_ntoa(d),
            ),
            ###############################################################
            FixedFieldSpec(
                "dst_addr",
                9,
                translator=lambda d: socket.inet_ntoa(d),
            ),
            ###############################################################
        ],
        header_size_calcurator=lambda d: d[1].value * 4,
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
        header_size_calcurator=lambda d: d[4].value * 4,
        optional_fields_spec=OptionalFieldsSpec(),
    ),
    "UDP": HeaderSpec(
        name="UDP",
        fixed_fields_format="!HHHH",
        fixed_fields_specs=[
            ###############################################################
            FixedFieldSpec("src_port", 0),
            ###############################################################
            FixedFieldSpec("dst_port", 1),
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
        header_size_calcurator=lambda d: 8 + d[1].value * 4,
        optional_fields_spec=OptionalFieldsSpec(
            fixed_fields_format="!HBB",
            fixed_fields_specs=[
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


class AWSGWLBAppliance:
    def __init__(
        self,
        protocol_header_spec_map: Dict[str, HeaderSpec],
        logger: logging.Logger,
    ) -> None:
        self.protocol_header_spec_map = protocol_header_spec_map
        self.logger = logger
        self.sockets: List[socket.socket] = []

    def __del__(self):
        for s in self.sockets:
            s.close()

    def run(self):
        #
        # UDP를 통해 GENEVE 패킷 수신을 하기 위해 소켓을 생성합니다.
        # - IP Hedaer 레벨의 수정이 요구되어, IP_HDRINCL를 이용합니다.
        #
        geneve_socket = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP
        )
        geneve_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        #
        # AWS GWLB의 health check를 처리하기 위한 소켓입니다.
        #
        tcp_socket = socket.socket(
            socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP
        )
        tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp_socket.bind(("0.0.0.0", 80))
        tcp_socket.listen()

        sockets = [geneve_socket, tcp_socket]

        closer = LoopCloser()

        while not closer.close_now:
            rs, _, _ = select.select(sockets, [], [], 3)
            for s in rs:
                if s == tcp_socket:
                    #
                    # 단순히 tcp socket에 응답만하면됩니다.
                    #
                    cs, _ = s.accept()
                    cs.recv(0)
                    cs.close()
                elif s == geneve_socket:
                    raw_data, _ = s.recvfrom(65536)

                    ############################################################
                    # OUT: IPv4 / UDP

                    outer_unpacked, outer_payloadpoint = self.unpack(
                        ["IPv4", "UDP"], raw_data
                    )
                    outer_ipv4_src_ip = (
                        outer_unpacked["IPv4"].fixed_fields[13].easy_value
                    )
                    outer_ipv4_dst_ip = (
                        outer_unpacked["IPv4"].fixed_fields[14].easy_value
                    )
                    outer_udp_src_port = (
                        outer_unpacked["UDP"].fixed_fields[0].easy_value
                    )
                    outer_udp_dst_port = (
                        outer_unpacked["UDP"].fixed_fields[1].easy_value
                    )

                    if outer_udp_dst_port != 6081:
                        #
                        # IPv4/UDP를 보고 있기 떄문에, GENEVE를 제외한 패킷은 무시합니다.
                        #
                        continue

                    s.sendto(
                        self.repack(raw_data, outer_ipv4_src_ip, outer_ipv4_dst_ip),
                        (outer_ipv4_src_ip, outer_udp_src_port),
                    )

                    print("-" * 64)

                    print(
                        f"[OUT:IPv4/UDP] {outer_ipv4_src_ip}:{outer_udp_src_port} -> {outer_ipv4_dst_ip}:{outer_udp_dst_port}"
                    )
                    outer_ipv4_total_length = (
                        outer_unpacked["IPv4"].fixed_fields[4].easy_value
                    )
                    print(f" - (IPv4) total_length: {outer_ipv4_total_length}")
                    ############################################################

                    ############################################################
                    # OUT: GENEVE

                    geneve_startpoint = outer_payloadpoint
                    geneve, geneve_payloadpoint = self.unpack(
                        ["Geneve"], raw_data[geneve_startpoint:]
                    )

                    print(f"[OUT:GENEVE]")
                    for group in geneve["Geneve"].optional_fields_groups:
                        print(
                            " ".join(
                                [
                                    f" - geneveoption/{group.group_index}:",
                                    f"class: {group.fields[0].easy_value},",
                                    f"type: {group.fields[1].easy_value},",
                                    f"value: {group.fields[-1].easy_value},",
                                ]
                            )
                        )
                    ############################################################

                    ############################################################
                    # IN: IPv4

                    inner_ipv4_startpoint = geneve_startpoint + geneve_payloadpoint
                    inner_ipv4_unpacked, inner_ipv4_payloadpoint = self.unpack(
                        ["IPv4"], raw_data[inner_ipv4_startpoint:]
                    )
                    inner_protocol = (
                        inner_ipv4_unpacked["IPv4"].fixed_fields[11].easy_value
                    )
                    inner_src_ip = (
                        inner_ipv4_unpacked["IPv4"].fixed_fields[13].easy_value
                    )
                    inner_dst_ip = (
                        inner_ipv4_unpacked["IPv4"].fixed_fields[14].easy_value
                    )
                    ############################################################

                    if inner_protocol == 6:
                        ############################################################
                        # IN: TCP

                        inner_tcp_startpoint = (
                            inner_ipv4_startpoint + inner_ipv4_payloadpoint
                        )
                        inner_tcp_unpacked, inner_tcp_pp = self.unpack(
                            ["TCP"], raw_data[inner_tcp_startpoint:]
                        )
                        inner_tcp_src_port = (
                            inner_tcp_unpacked["TCP"].fixed_fields[0].easy_value
                        )
                        inner_tcp_dst_port = (
                            inner_tcp_unpacked["TCP"].fixed_fields[1].easy_value
                        )
                        inner_tcp_options = self.parse_tcp_options(
                            inner_tcp_unpacked["TCP"].optional_fields_raw
                        )
                        inner_tcp_flags = {
                            "urg": inner_tcp_unpacked["TCP"].fixed_fields[5].value,
                            "ack": inner_tcp_unpacked["TCP"].fixed_fields[6].value,
                            "psh": inner_tcp_unpacked["TCP"].fixed_fields[7].value,
                            "rst": inner_tcp_unpacked["TCP"].fixed_fields[8].value,
                            "syn": inner_tcp_unpacked["TCP"].fixed_fields[9].value,
                            "fin": inner_tcp_unpacked["TCP"].fixed_fields[10].value,
                        }
                        inner_tcp_set_flags = [
                            key for key, value in inner_tcp_flags.items() if value > 0
                        ]

                        print(
                            f"[IN:IPv4/TCP] {inner_src_ip}:{inner_tcp_src_port} -> {inner_dst_ip}:{inner_tcp_dst_port}"
                        )
                        inner_ipv4_total_length = (
                            inner_ipv4_unpacked["IPv4"].fixed_fields[4].easy_value
                        )
                        print(f" - (IPv4) total_length: {inner_ipv4_total_length}")
                        print(
                            " ".join(
                                [
                                    " - (TCP) flags:",
                                ]
                                + inner_tcp_set_flags
                            )
                        )
                        for key, value in inner_tcp_options.items():
                            print(f" - (TCP) option: {key} / {value}")
                        print(
                            f" - (TCP) payload: {raw_data[inner_tcp_startpoint + inner_tcp_pp:]}"
                        )
                        ############################################################
                    elif inner_protocol == 17:
                        ############################################################
                        # IN: UDP

                        inner_udp_startpoint = (
                            inner_ipv4_startpoint + inner_ipv4_payloadpoint
                        )
                        inner_udp_unpacked, inner_udp_pp = self.unpack(
                            ["UDP"], raw_data[inner_udp_startpoint:]
                        )
                        inner_udp_src_port = (
                            inner_udp_unpacked["UDP"].fixed_fields[0].easy_value
                        )
                        inner_udp_dst_port = (
                            inner_udp_unpacked["UDP"].fixed_fields[1].easy_value
                        )
                        print(
                            f"[IN:IPv4/UDP] {inner_src_ip}:{inner_udp_src_port} -> {inner_dst_ip}:{inner_udp_dst_port}"
                        )
                        print(
                            f" - (UDP) payload: {raw_data[inner_udp_startpoint + inner_udp_pp:]}"
                        )
                        ############################################################
                    else:
                        ############################################################
                        # IN: Unknown

                        print(f"[IN:IPv4] {inner_src_ip} -> {inner_dst_ip}")
                        print(
                            f"[IN:Unknown] inner-packet is not supported protocol: {inner_protocol}"
                        )
                        ############################################################

    def unpack(
        self, protocol_orders: List[str], raw_data: bytes
    ) -> Tuple[Dict[str, Header], int]:
        raw_data_pointer = 0

        unpacked_headers = {}
        for proto in protocol_orders:
            spec = self.protocol_header_spec_map.get(proto)
            #
            # Unpack
            #
            unpacked_header = self.analyze_header(spec, raw_data, raw_data_pointer)
            unpacked_headers[proto] = unpacked_header
            #
            # Add pointer
            #
            raw_data_pointer += unpacked_header.header_size

        return unpacked_headers, raw_data_pointer

    def analyze_header(
        self, spec: HeaderSpec, raw_data: bytes, raw_data_pointer: int
    ) -> Header:
        #
        # fixed-field의 크기를 계산하고, raw_data를 자릅니다.
        #
        fixed_fields_size = struct.calcsize(spec.fixed_fields_format)
        fixed_fields_raw = raw_data[
            raw_data_pointer : raw_data_pointer + fixed_fields_size
        ]
        #
        # fixed-field를 추출합니다.
        #
        unpacked_fixed_fields = struct.unpack(
            spec.fixed_fields_format, fixed_fields_raw
        )
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
                    easy_value=(
                        field_spec.translator(value)
                        if field_spec.translator is not None
                        else value
                    ),
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

        if opt_spec.fixed_fields_format is None or opt_spec.fixed_fields_specs is None:
            #
            # optional-field에 대한 포맷과 스펙이 정의되지 않은 경우 하나의 field로 추출합니다.
            #
            group = OptionalFieldsGroup(group_index=0)

            if isinstance(opt_fields_raw, bytes):
                easy_value = opt_fields_raw.hex()
            elif isinstance(opt_fields_raw, int):
                easy_value = hex(opt_fields_raw)
            else:
                easy_value = str(opt_fields_raw)

            group.fields.append(
                FixedField(
                    name=f"-",
                    field_index=0,
                    unpack_index=0,
                    value=opt_fields_raw,
                    easy_value=easy_value,
                )
            )
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
                    opt_fields_raw[pointer : pointer + fixed_group_size],
                )
                group = OptionalFieldsGroup(group_index=group_count)

                for field_index, field_spec in enumerate(opt_spec.fixed_fields_specs):
                    value = field_spec.unpakcer(unpacked[field_spec.unpack_index])

                    if isinstance(value, bytes):
                        easy_value = value.hex()
                    elif isinstance(value, int):
                        easy_value = hex(value)
                    else:
                        easy_value = str(value)

                    group.fields.append(
                        FixedField(
                            name=field_spec.name,
                            field_index=field_index,
                            unpack_index=field_spec.unpack_index,
                            value=value,
                            easy_value=easy_value,
                        )
                    )

                remain_field_size = opt_spec.remain_field_size_calcurator(group.fields)
                if remain_field_size > 0:
                    value = opt_fields_raw[
                        pointer
                        + fixed_group_size : pointer
                        + fixed_group_size
                        + remain_field_size
                    ]

                    if isinstance(value, bytes):
                        easy_value = value.hex()
                    elif isinstance(value, int):
                        easy_value = hex(value)
                    else:
                        easy_value = str(value)

                    group.fields.append(
                        FixedField(
                            name=f"-",
                            field_index=len(group.fields),
                            unpack_index=len(group.fields),
                            value=value,
                            easy_value=easy_value,
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

    def get_ipv4_checksum(self, header: bytes) -> int:
        s = 0
        for i in range(0, len(header), 2):
            w = (header[i] << 8) + (header[i + 1] if i + 1 < len(header) else 0)
            s += w
        s = (s >> 16) + (s & 0xFFFF)
        s += s >> 16
        return ~s & 0xFFFF

    def parse_tcp_options(self, raw_data: bytes) -> dict[str:any]:
        options = {}
        pointer = 0
        while pointer < len(raw_data):
            kind = raw_data[pointer]

            if kind == 0:
                #
                # End of Options List
                #
                break
            elif kind == 1:
                #
                # NOP (No Operation)
                #
                pointer += 1
                continue
            else:
                if pointer + 1 >= len(raw_data):
                    # Something wrong
                    break

                length = raw_data[pointer + 1]
                if length < 2:
                    # Something wrong
                    break

                data = raw_data[pointer + 2 : pointer + length]

                if kind == 2:
                    #
                    # MSS
                    #
                    mss = struct.unpack("!H", data)[0]
                    options["MSS"] = mss

                pointer += length

        return options

    def repack(self, raw_data: bytes, source_ip: str, destination_ip: str) -> bytearray:
        #
        # https://aws.amazon.com/ko/blogs/networking-and-content-delivery/integrate-your-custom-logic-or-appliance-with-aws-gateway-load-balancer/
        #
        # 1. encapsulate the original packet inside Geneve header
        # 2. swap the source and destination IP addresses in outer IPv4 header (i.e. Source IP = appliance IP address. Destination IP = GWLB IP address)
        # 3. preserve original ports and must not swap the source and destination ports in outer IPv4 header
        # 4. update the IP checksum in outer IPv4 header
        # 5. return the packet to GWLB with the TLVs intact for the given 5-tuple of the original inside packet.
        #

        ipv4_spec = self.protocol_header_spec_map["IPv4"]

        outer_ipv4_header = self.analyze_header(ipv4_spec, raw_data, 0)
        outer_ipv4_header_size = outer_ipv4_header.header_size

        repacked_packet = bytearray(raw_data)
        repacked_packet[10:12] = b"\x00\x00"  # Checksum
        repacked_packet[12:16] = socket.inet_aton(destination_ip)  # Source IP
        repacked_packet[16:20] = socket.inet_aton(source_ip)  # Destination IP

        checksum = self.get_ipv4_checksum(repacked_packet[:outer_ipv4_header_size])
        struct.pack_into("!H", repacked_packet, 10, checksum)

        return repacked_packet


appliance = AWSGWLBAppliance(PROTOCOL_MAP, LOGGER)
appliance.run()
