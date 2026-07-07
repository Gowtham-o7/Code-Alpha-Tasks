"""
Display Module
Handles all terminal output with color-coding and formatting.
"""

from datetime import datetime


class Colors:
    """ANSI color codes for terminal output."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    GREY    = "\033[90m"
    BG_RED  = "\033[41m"


PROTOCOL_COLORS = {
    "TCP":     Colors.GREEN,
    "UDP":     Colors.BLUE,
    "ICMP":    Colors.YELLOW,
    "ARP":     Colors.MAGENTA,
    "DNS":     Colors.CYAN,
    "HTTP":    Colors.RED,
    "UNKNOWN": Colors.GREY,
}


class PacketDisplay:
    """Formats and prints packet information to the terminal."""

    BANNER = r"""
  _   _      _                      _      ____        _  __  __
 | \ | | ___| |___      _____  _ __| | __ / ___| _ __ (_)/ _|/ _| ___ _ __
 |  \| |/ _ \ __\ \ /\ / / _ \| '__| |/ / \___ \| '_ \| | |_| |_ / _ \ '__|
 | |\  |  __/ |_ \ V  V / (_) | |  |   <   ___) | | | | |  _|  _|  __/ |
 |_| \_|\___|\__| \_/\_/ \___/|_|  |_|\_\ |____/|_| |_|_|_| |_|  \___|_|
    """

    def __init__(self, use_color=True, verbose=False):
        self.use_color = use_color
        self.verbose = verbose

    def _color(self, text, color):
        if self.use_color:
            return f"{color}{text}{Colors.RESET}"
        return text

    def print_banner(self):
        print(self._color(self.BANNER, Colors.CYAN))
        print(self._color("  Basic Network Sniffer | Educational Tool | Use Responsibly\n", Colors.GREY))

    def print_config(self, args):
        print(self._color("[CONFIG]", Colors.BOLD + Colors.WHITE))
        print(f"  Interface : {args.interface or 'auto-detect'}")
        print(f"  Filter    : {args.filter or 'None'}")
        print(f"  Protocol  : {args.protocol}")
        print(f"  Count     : {'Unlimited' if args.count == 0 else args.count}")
        print(f"  Output    : {args.output or 'None'}")
        print(f"  Verbose   : {args.verbose}")
        print()
        # Column headers
        header = f"{'#':<6} {'Time':<14} {'Proto':<8} {'Source':<22} {'Destination':<22} {'Info'}"
        print(self._color(header, Colors.BOLD + Colors.WHITE))
        print(self._color("-" * 90, Colors.GREY))

    def print_packet(self, info):
        """Print a single parsed packet to stdout."""
        proto_color = PROTOCOL_COLORS.get(info.protocol, Colors.WHITE)
        proto_str = self._color(f"{info.protocol:<8}", proto_color + Colors.BOLD)

        src = self._format_endpoint(info.src_ip, info.src_port, info.src_mac, info.protocol)
        dst = self._format_endpoint(info.dst_ip, info.dst_port, info.dst_mac, info.protocol)
        detail = self._format_detail(info)

        line = f"{info.packet_num:<6} {info.timestamp:<14} {proto_str} {src:<22} {dst:<22} {detail}"
        print(line)

        # Verbose: payload
        if self.verbose and info.payload:
            print(self._color(f"         Payload: {info.payload[:200]}", Colors.GREY))

    def print_statistics(self, stats):
        """Print a summary statistics table."""
        print()
        print(self._color("=" * 50, Colors.CYAN))
        print(self._color("  CAPTURE STATISTICS", Colors.BOLD + Colors.WHITE))
        print(self._color("=" * 50, Colors.CYAN))
        print(f"  Total Packets : {stats['total']}")
        print(f"  Total Bytes   : {stats['bytes']:,}")
        print()
        rows = [
            ("TCP",   stats["tcp"],   Colors.GREEN),
            ("UDP",   stats["udp"],   Colors.BLUE),
            ("ICMP",  stats["icmp"],  Colors.YELLOW),
            ("ARP",   stats["arp"],   Colors.MAGENTA),
            ("DNS",   stats["dns"],   Colors.CYAN),
            ("HTTP",  stats["http"],  Colors.RED),
            ("Other", stats["other"], Colors.GREY),
        ]
        for name, count, color in rows:
            bar_len = int((count / max(stats["total"], 1)) * 20)
            bar = "█" * bar_len
            pct = (count / max(stats["total"], 1)) * 100
            print(f"  {self._color(f'{name:<6}', color)} {count:>5}  {bar:<20} {pct:.1f}%")
        print(self._color("=" * 50, Colors.CYAN))

    # ------------------------------------------------------------------ #
    #  Private helpers                                                     #
    # ------------------------------------------------------------------ #

    def _format_endpoint(self, ip, port, mac, protocol):
        if protocol == "ARP":
            return mac or ""
        if ip and port:
            return f"{ip}:{port}"
        return ip or mac or ""

    def _format_detail(self, info):
        """Build a human-readable detail string."""
        p = info.protocol

        if p == "TCP":
            flags = info.tcp_flags or ""
            return f"Flags={flags} Seq={info.seq_num} Win={info.window_size} Len={info.length}"

        elif p == "UDP":
            return f"Len={info.length}"

        elif p == "ICMP":
            return f"{info.icmp_type_name} (type={info.icmp_type} code={info.icmp_code})"

        elif p == "ARP":
            return f"{info.arp_op}: {info.arp_src_ip} → {info.arp_dst_ip}"

        elif p == "DNS":
            if info.dns_type == "Query":
                return f"Query: {info.dns_query}"
            else:
                return f"Response: {info.dns_response}"

        elif p == "HTTP":
            if info.http_method:
                return f"{info.http_method} {info.http_host}{info.http_path}"
            elif info.http_status:
                return f"Response {info.http_status}"

        return f"Len={info.length}"
