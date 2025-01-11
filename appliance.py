import signal
import socket
import select
import struct
from typing import List, Dict, Callable
from dataclasses import dataclass, field
from datetime import datetime


DUMMY_LAMBDA = lambda d: d


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


PROTOCOL_MAP: Dict[str, HeaderSpec] = {
    "IPv4": HeaderSpec(
        name="IPv4",
        fixed_fields_format="!BBHHHBBH4s4s",
        fixed_fields_specs=[
            FixedFieldSpec("version", 0, unpakcer=lambda d: d >> 4),
            FixedFieldSpec("ihl", 0, unpakcer=lambda d: d & 0xF),
            FixedFieldSpec("dscp", 1, unpakcer=lambda d: d >> 2),
            FixedFieldSpec("ecn", 1, unpakcer=lambda d: d & 0x3),
            FixedFieldSpec("total_length", 2),
            FixedFieldSpec("id", 3),
            FixedFieldSpec("flag_x", 4, unpakcer=lambda d: d >> 15 & 1),
            FixedFieldSpec("flag_d", 4, unpakcer=lambda d: d >> 14 & 1),
            FixedFieldSpec("flag_m", 4, unpakcer=lambda d: d >> 13 & 1),
            FixedFieldSpec("frag_offset", 4, unpakcer=lambda d: d & 0x2000),
            FixedFieldSpec("ttl", 5),
            FixedFieldSpec("protocol", 6),
            FixedFieldSpec("checksum", 7),
            FixedFieldSpec(
                "src_addr",
                8,
                translator=lambda d: socket.inet_ntoa(d),
            ),
            FixedFieldSpec(
                "dst_addr",
                9,
                translator=lambda d: socket.inet_ntoa(d),
            ),
        ],
        header_size_calcurator=lambda d: d[1].value * 4,
        optional_fields_spec=OptionalFieldsSpec(),
    ),
    "TCP": HeaderSpec(
        name="TCP",
        fixed_fields_format="!HHIIHHHH",
        fixed_fields_specs=[
            FixedFieldSpec("src_port", 0),
            FixedFieldSpec("dst_port", 1),
            FixedFieldSpec("seq", 2),
            FixedFieldSpec("ack", 3),
            FixedFieldSpec("offset", 4, unpakcer=lambda d: d >> 12),
            FixedFieldSpec("urg", 4, unpakcer=lambda d: d >> 5 & 0x1),
            FixedFieldSpec("ack", 4, unpakcer=lambda d: d >> 4 & 0x1),
            FixedFieldSpec("psh", 4, unpakcer=lambda d: d >> 3 & 0x1),
            FixedFieldSpec("rst", 4, unpakcer=lambda d: d >> 2 & 0x1),
            FixedFieldSpec("syn", 4, unpakcer=lambda d: d >> 1 & 0x1),
            FixedFieldSpec("fin", 4, unpakcer=lambda d: d & 0x1),
            FixedFieldSpec("window", 5),
            FixedFieldSpec("checksum", 6),
            FixedFieldSpec("urg_pointer", 7),
        ],
        header_size_calcurator=lambda d: d[4].value * 4,
        optional_fields_spec=OptionalFieldsSpec(),
    ),
    "UDP": HeaderSpec(
        name="UDP",
        fixed_fields_format="!HHHH",
        fixed_fields_specs=[
            FixedFieldSpec("src_port", 0),
            FixedFieldSpec("dst_port", 1),
            FixedFieldSpec("length", 2),
            FixedFieldSpec("checksum", 3),
        ],
        optional_fields_spec=OptionalFieldsSpec(),
    ),
    "Geneve": HeaderSpec(
        name="Geneve",
        fixed_fields_format="!BBH3sB",
        fixed_fields_specs=[
            FixedFieldSpec("version", 0, unpakcer=lambda d: d >> 6),
            FixedFieldSpec("options_length", 0, unpakcer=lambda d: d & 0x3F),
            FixedFieldSpec("control", 1, unpakcer=lambda d: d >> 7),
            FixedFieldSpec("critical", 1, unpakcer=lambda d: d >> 6 & 0x1),
            FixedFieldSpec("protocol", 2),
            FixedFieldSpec("vni", 3),
            FixedFieldSpec("reserved", 4),
        ],
        header_size_calcurator=lambda d: 8 + d[1].value * 4,
        optional_fields_spec=OptionalFieldsSpec(
            fixed_fields_format="!HBB",
            fixed_fields_specs=[
                FixedFieldSpec("option_class", 0),
                FixedFieldSpec("option_type", 1),
                FixedFieldSpec("critical", 1, unpakcer=lambda d: d >> 7),
                FixedFieldSpec("option_length", 2, unpakcer=lambda d: d & 0x1F),
            ],
            remain_field_size_calcurator=lambda d: d[3].value * 4,
        ),
    ),
}


class ProtocolParser:
    def __init__(self, protocol_header_spec_map: Dict[str, HeaderSpec]):
        self.protocol_header_spec_map = protocol_header_spec_map

    def report_ipv4(self, raw_data: bytes):
        ipv4_header = self.parse_protocol_hedaer("IPv4", raw_data)
        payload_protocol = ipv4_header.fixed_fields[11].value

        if payload_protocol == 6:
            self.report_ipv4_tcp(raw_data, ipv4_header)
        elif payload_protocol == 17:
            self.report_ipv4_udp(raw_data, ipv4_header)
        else:
            self.report_unknown(raw_data, ipv4_header)

    def report_ipv4_tcp(self, raw_data: bytes, ipv4_header: Header):
        ipv4_src_addr = ipv4_header.fixed_fields[13].easy_value
        ipv4_dst_addr = ipv4_header.fixed_fields[14].easy_value
        ipv4_total_length = ipv4_header.fixed_fields[4].easy_value
        ipv4_payload = raw_data[ipv4_header.header_size :]

        tcp_header = self.parse_protocol_hedaer("TCP", ipv4_payload)
        tcp_src_port = tcp_header.fixed_fields[0].easy_value
        tcp_dst_port = tcp_header.fixed_fields[1].easy_value
        tcp_paylaod = raw_data[ipv4_header.header_size + tcp_header.header_size :]
        tcp_options = self.parse_tcp_options(tcp_header.optional_fields_raw)
        tcp_flags: List[str] = []
        for index in range(5, 11):
            flag = tcp_header.fixed_fields[index]
            if flag.value > 0:
                tcp_flags.append(flag.name)

        print(
            f"[IPv4/TCP] {ipv4_src_addr}:{tcp_src_port} -> {ipv4_dst_addr}:{tcp_dst_port}"
        )
        print(f" - (IPv4) total-length: {ipv4_total_length}")
        print(f" - (TCP) flags: {' '.join(tcp_flags)}")
        for key, value in tcp_options.items():
            print(f" - (TCP) option: {key}:{value}")
        print(f" - (TCP) payload: {tcp_paylaod}")

    def report_ipv4_udp(self, raw_data: bytes, ipv4_header: Header):
        ipv4_src_addr = ipv4_header.fixed_fields[13].easy_value
        ipv4_dst_addr = ipv4_header.fixed_fields[14].easy_value
        ipv4_total_length = ipv4_header.fixed_fields[4].easy_value
        ipv4_payload = raw_data[ipv4_header.header_size :]

        udp_header = self.parse_protocol_hedaer("UDP", ipv4_payload)
        udp_src_port = udp_header.fixed_fields[0].easy_value
        udp_dst_port = udp_header.fixed_fields[1].easy_value
        udp_paylaod = raw_data[ipv4_header.header_size + udp_header.header_size :]

        print(
            f"[IPv4/UDP] {ipv4_src_addr}:{udp_src_port} -> {ipv4_dst_addr}:{udp_dst_port}"
        )
        print(f" - (IPv4) total-length: {ipv4_total_length}")

        if udp_dst_port == 6081:
            #
            #
            self.report_ipv4_geneve(udp_paylaod)

        else:
            print(f" - (UDP) payload: {udp_paylaod}")

    def report_ipv4_geneve(self, raw_data: bytes):
        geneve_header = self.parse_protocol_hedaer("Geneve", raw_data)
        geneve_payload = raw_data[geneve_header.header_size :]

        print(f"[GENEVE]")
        for group in geneve_header.optional_fields_groups:
            print(
                " ".join(
                    [
                        f" - geneveoption/{group.group_index}:",
                        f"class:{group.fields[0].easy_value}",
                        f"type:{group.fields[1].easy_value}",
                        f"value:{group.fields[-1].easy_value}",
                    ]
                )
            )

        self.report_ipv4(geneve_payload)

    def report_unknown(self, raw_data: bytes, ipv4_header: Header):
        ipv4_src_addr = ipv4_header.fixed_fields[13].easy_value
        ipv4_dst_addr = ipv4_header.fixed_fields[14].easy_value
        ipv4_paylaod = raw_data[ipv4_header.header_size]

        print(f"[IPv4/UNKNOWN] {ipv4_src_addr} -> {ipv4_dst_addr}")
        print(f" - (IPv4) payload: {ipv4_paylaod}")

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

    def parse_protocol_hedaer(self, protocol_name: str, raw_data: bytes) -> Header:
        spec = self.protocol_header_spec_map.get(protocol_name)

        #
        # fixed-field의 크기를 계산하고, raw_data를 자릅니다.
        #
        fixed_fields_size = struct.calcsize(spec.fixed_fields_format)
        fixed_fields_raw = raw_data[:fixed_fields_size]

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
        opt_fields_start = fixed_fields_size
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


class LoopCloser:
    def __init__(self):
        self.close_now = False
        signal.signal(signal.SIGINT, self.set_close_now_flag)
        signal.signal(signal.SIGTERM, self.set_close_now_flag)

    def set_close_now_flag(self, *args):
        self.close_now = True
        print("[*] Success to escape loop")


class AWSGWLBAppliance:
    def __init__(
        self, protocol_header_spec_map: Dict[str, HeaderSpec], verbose: bool = False
    ) -> None:
        self.sockets: List[socket.socket] = []
        self.protocol_parser = ProtocolParser(protocol_header_spec_map)
        self.verbose = verbose

    def __del__(self):
        for s in self.sockets:
            s.close()

    def run(self) -> None:
        #
        # UDP를 통해 GENEVE 패킷 수신을 하기 위해 소켓을 생성합니다.
        # - IP/UDP Header 수정이 요구되어, IP_HDRINCL를 이용합니다.
        #
        geneve_socket = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP
        )
        geneve_socket.setsockopt(
            socket.IPPROTO_IP,
            socket.IP_HDRINCL,  # IP-Hedaer-Included
            1,
        )
        self.sockets.append(geneve_socket)

        #
        # AWS GWLB의 health check를 처리하기 위한 소켓입니다.
        #
        healthcheck_socket = socket.socket(
            socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP
        )
        healthcheck_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        healthcheck_socket.bind(("0.0.0.0", 80))
        healthcheck_socket.listen()
        self.sockets.append(healthcheck_socket)

        #
        # 소켓으로 수신되는 데이터를 처리합니다.
        #
        closer = LoopCloser()
        while not closer.close_now:
            rs: List[socket.socket] = []
            rs, _, _ = select.select(self.sockets, [], [], 3)

            for s in rs:
                if s == healthcheck_socket:
                    self.healthcheck_handler(s)
                elif s == geneve_socket:
                    self.geneve_handler(s, datetime.now())

    def healthcheck_handler(self, s: socket.socket) -> None:
        #
        # 단순하게 TCP 세션만 맺고 닫아도 된다.
        #
        cs, _ = s.accept()
        cs.recv(0)
        cs.close()

    def geneve_handler(self, s: socket.socket, t: datetime) -> None:
        raw_data, addr = s.recvfrom(65536)

        #
        # 패킷을 분석해서, 응답해야할 패킷인지 확인합니다.
        #
        outer_ipv4_ihl = raw_data[0] & 0x0F
        outer_ipv4_header_length = outer_ipv4_ihl * 4
        outer_udp_dst_port = int.from_bytes(
            raw_data[outer_ipv4_header_length + 2 : outer_ipv4_header_length + 4],
            byteorder="big",
        )
        if outer_udp_dst_port != 6081:
            return

        #
        # GWLB로 응답하기 위한 패킷을 조립합니다.
        # - 1. IPv4의 출발지주소, 목적지주소 교환 후, 체크섬 다시 계산
        # - 2. UDP/GENEVE의 패킷은 그대로 유지
        #
        resp = bytearray(raw_data)
        resp[12:16], resp[16:20] = resp[16:20], resp[12:16]
        resp[10], resp[11] = 0, 0
        resp_checksum = self.calc_ipv4_checksum(resp[:outer_ipv4_header_length])
        struct.pack_into("!H", resp, 10, resp_checksum)

        #
        # GWLB로 응답합니다.
        # - 현재 소켓 설정에 의해 addr은 (출발지주소, 0)으로 설정됩니다만, 커널이 알아서 꽂아줍니다.
        #
        s.sendto(resp, addr)

        #
        # STDOUT으로 reporting 합니다.
        # - `tcpdump -nnvvXS -i ens5 udp port 6081`
        # -
        #
        if self.verbose:
            print(f"[Rough-Timestamp] {t.strftime('%Y-%m-%d %H:%M:%S.%f')}")
            self.protocol_parser.report_ipv4(raw_data)
            print("")

    def calc_ipv4_checksum(self, header: bytes) -> int:
        s = 0
        for i in range(0, len(header), 2):
            w = (header[i] << 8) + (header[i + 1] if i + 1 < len(header) else 0)
            s += w
        s = (s >> 16) + (s & 0xFFFF)
        s += s >> 16
        return ~s & 0xFFFF


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose mode"
    )
    args = parser.parse_args()
    verbose: bool = args.verbose

    appliance = AWSGWLBAppliance(PROTOCOL_MAP, verbose)
    appliance.run()
