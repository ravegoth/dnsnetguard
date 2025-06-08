#!/usr/bin/env python3

import argparse
import logging
import struct
import sys
import re
from threading import Lock

# conditional import of third-party libraries.
# this block ensures that necessary libraries are installed before execution.
try:
    import pydivert
    from dnslib import DNSRecord
    from colorama import init, Fore, Style
except ImportError as e:
    # provides a user-friendly error message if a required library is missing.
    print(f"error: missing required library. please run 'pip install {e.name}'")
    sys.exit(1)

# import domain patterns from a separate configuration file for better modularity.
from domains import DOMAIN_PATTERNS


class Config:
    """
    manages application-wide configuration settings.
    this centralizes mutable and immutable parameters, making the application easier to configure.
    """
    LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'
    DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
    # defines color mappings for different logging levels for enhanced readability.
    LOG_COLORS = {
        logging.DEBUG: Style.DIM + Fore.CYAN,
        logging.INFO: Fore.GREEN,
        logging.WARNING: Fore.YELLOW,
        logging.ERROR: Fore.RED,
        logging.CRITICAL: Fore.RED + Style.BRIGHT,
    }


class ColorFormatter(logging.Formatter):
    """
    custom logging formatter to add color to console output.
    this improves the visual distinction of log messages based on their severity.
    """
    def __init__(self, fmt=None, datefmt=None, style='%'):
        super().__init__(fmt, datefmt, style)
        self.log_colors = Config.LOG_COLORS

    def format(self, record):
        """
        formats the log record, applying the appropriate color based on its level.
        """
        color = self.log_colors.get(record.levelno, Fore.WHITE)
        # applies color to the message and resets it afterwards.
        record.msg = f"{color}{record.msg}{Style.RESET_ALL}"
        return super().format(record)


# initialize colorama for cross-platform terminal coloring.
init()

# configure the root logger with the custom formatter.
# this ensures all log messages use the defined formatting.
handler = logging.StreamHandler()
handler.setFormatter(ColorFormatter(fmt=Config.LOG_FORMAT, datefmt=Config.DATE_FORMAT))

# custom logger for dnsnetguard to avoid interfering with other library logs.
log = logging.getLogger('dnsnetguard')
log.setLevel(logging.INFO)  # default logging level.
log.addHandler(handler)
log.propagate = False  # prevents messages from being passed to the root logger.


class DomainDatabase:
    """
    manages and provides lookup functionality for suspicious and whitelisted domain patterns.
    regular expressions are pre-compiled for efficient matching.
    """
    def __init__(self):
        self.patterns = {}
        self._compile_patterns()

    def _compile_patterns(self):
        """
        compiles regular expression patterns from the imported domain_patterns.
        each pattern is stored under its respective category.
        """
        for category, patterns_list in DOMAIN_PATTERNS.items():
            # compiles each regex string into a regex object.
            self.patterns[category] = [re.compile(p) for p in patterns_list]

    def check_domain(self, domain: str) -> tuple[str | None, str | None]:
        """
        checks a given domain against predefined pattern categories.
        the order of checks is critical: whitelist -> malware -> spyware -> adware.

        args:
            domain (str): the domain name to check.

        returns:
            tuple[str | None, str | None]: a tuple containing the matched category and
                                           the exact pattern string that matched, or (none, none)
                                           if no match is found.
        """
        # 1. prioritize whitelisted domains to prevent legitimate traffic from being blocked.
        for pattern in self.patterns.get("WHITELIST", []):
            if pattern.match(domain):
                return "WHITELISTED", pattern.pattern

        # 2. check high-priority threat categories (malware command & control).
        for pattern in self.patterns.get("MALWARE_C2", []):
            if pattern.match(domain):
                return "MALWARE", pattern.pattern

        # 3. check for telemetry and spyware domains.
        for pattern in self.patterns.get("TELEMETRY/SPYWARE", []):
            if pattern.match(domain):
                return "SPYWARE", pattern.pattern
        
        # 4. check for adware and trackers.
        for pattern in self.patterns.get("ADWARE/TRACKER", []):
            if pattern.match(domain):
                return "ADWARE", pattern.pattern

        # no match found in any category.
        return None, None


class PacketInterceptor:
    """
    captures, analyzes, and optionally blocks network packets based on configured rules.
    it inspects dns queries and tls sni handshakes to identify domain names.
    """
    def __init__(self, block_mode: bool = False, verbose: bool = False):
        self.db = DomainDatabase()
        self.block_mode = block_mode
        self.lock = Lock()  # used for thread-safe access to statistics.
        # initializes performance statistics.
        self.stats = {
            "processed": 0, "allowed": 0,
            "blocked": 0, "detected": 0
        }
        # adjusts logging level based on the verbose flag.
        log.setLevel(logging.DEBUG if verbose else logging.INFO)
        # simplified filter rule: capture all outbound traffic.
        self.filter_rule = "outbound"

    def _extract_sni(self, data: bytes) -> str | None:
        """
        extracts the server name indication (sni) hostname from a tls client hello packet.
        this involves parsing the tls handshake protocol.

        args:
            data (bytes): the payload of the tcp packet.

        returns:
            str | None: the extracted sni hostname in lowercase, or none if not found or parsing fails.
        """
        try:
            # basic check for tls client hello (handshake type 0x16, tls version 0x0301, handshake message type 0x01).
            if not (len(data) > 5 and data[0] == 0x16 and data[1] == 0x03 and data[5] == 0x01):
                return None
            
            idx = 43  # starting index for session id length.
            session_id_len = data[idx]
            idx += 1 + session_id_len
            
            cipher_len = struct.unpack('!h', data[idx:idx+2])[0]
            idx += 2 + cipher_len
            
            comp_methods_len = data[idx]
            idx += 1 + comp_methods_len
            
            extensions_len = struct.unpack('!h', data[idx:idx+2])[0]
            idx += 2
            extensions_end = idx + extensions_len

            # iterates through tls extensions to find the sni extension (type 0).
            while idx + 4 <= extensions_end:
                ext_type, ext_len = struct.unpack('!hh', data[idx:idx+4])
                if ext_type == 0:  # server_name extension.
                    # this length refers to the length of the server_name_list.
                    server_name_list_len = struct.unpack('!h', data[idx+4:idx+6])[0]
                    # the first byte (data[idx+6]) is the name type, typically 0 for hostname.
                    if data[idx+6] == 0: # hostname type.
                        server_name_len = struct.unpack('!h', data[idx+7:idx+9])[0]
                        # extracts and decodes the server name.
                        server_name = data[idx+9:idx+9+server_name_len].decode('utf-8')
                        return server_name.lower()
                idx += 4 + ext_len  # moves to the next extension.
        except (struct.error, IndexError, UnicodeDecodeError) as e: # Corrected UnicodeDecodeError
            # catches potential errors during parsing, indicating a malformed packet.
            log.debug(f"sni extraction error: {e}")
            return None
        return None

    def _process_packet(self, packet: pydivert.Packet) -> bool:
        """
        analyzes a single captured packet to determine if it should be allowed or blocked.
        this is the core logic for domain identification and rule application.

        args:
            packet (pydivert.Packet): the captured packet object.

        returns:
            bool: true if the packet should be allowed, false if it should be blocked.
        """
        domain = None
        protocol = "unknown"

        with self.lock:
            self.stats["processed"] += 1

        # first, check if the packet is relevant (DNS or TLS) before proceeding.
        if packet.udp and packet.dst_port == 53:
            try:
                dns_req = DNSRecord.parse(packet.payload)
                # ensures it's a dns query (not a response) and has at least one question.
                if dns_req.header.qr == 0 and dns_req.questions:
                    domain = str(dns_req.q.qname).strip(".").lower()
                    protocol = "dns"
            except Exception as e:
                # logs and ignores malformed dns packets.
                log.debug(f"malformed dns packet ignored: {e}")
            
        elif packet.tcp and packet.dst_port == 443 and len(packet.payload) > 0:
            sni_host = self._extract_sni(packet.payload)
            if sni_host:
                domain = sni_host
                protocol = "tls/sni"
        else:
            # if the packet is not dns or tls, it's allowed immediately.
            with self.lock:
                self.stats["allowed"] += 1
            log.debug(f"allowed (irrelevant port) | from: {packet.src_addr}:{packet.src_port} "
                      f"to: {packet.dst_addr}:{packet.dst_port}")
            return True


        # if no domain can be identified from the relevant packet, it is allowed by default.
        if not domain:
            log.debug(f"allowed (no domain identified in relevant packet) | from: {packet.src_addr}:{packet.src_port} "
                      f"to: {packet.dst_addr}:{packet.dst_port}")
            with self.lock:
                self.stats["allowed"] += 1
            return True

        # checks the identified domain against the domain database.
        category, pattern = self.db.check_domain(domain)

        # actions based on domain categorization.
        if category and category != "WHITELISTED":
            log_msg = (f"[{protocol:^7}] {domain:<50} | "
                       f"category: {category:<10} | match: {pattern}")
            
            if self.block_mode:
                log.warning(f"blocked   {log_msg}")
                with self.lock:
                    self.stats["blocked"] += 1
                return False  # packet is explicitly blocked.
            else:
                log.error(f"detected  {log_msg}")
                with self.lock:
                    self.stats["detected"] += 1
        else:
            # logs allowed traffic, especially in verbose mode.
            log.debug(f"allowed   [{protocol:^7}] {domain:<50} | to: {packet.dst_addr}")
            with self.lock:
                self.stats["allowed"] += 1
                
        return True  # packet is allowed.

    def run(self):
        """
        initiates the packet interception loop.
        requires administrator privileges to function.
        """
        mode = "block" if self.block_mode else "monitor"
        log.critical(f">> dnsnetguard starting in {mode} mode. press ctrl+c to exit.")
        
        try:
            # uses pydivert to capture and reinject packets.
            # filter_rule is now simply "outbound".
            with pydivert.WinDivert(self.filter_rule) as w:
                for packet in w:
                    if self._process_packet(packet):
                        # if the packet is allowed, send it back into the network stream.
                        w.send(packet)
        except OSError as e:
            # catches os errors, typically related to missing administrator privileges.
            log.critical(f"os error: {e}. this tool requires administrator privileges.")
            sys.exit(1)
        except KeyboardInterrupt:
            # handles graceful shutdown on ctrl+c.
            self.shutdown()
        except Exception as e:
            # catches any other unexpected errors during runtime.
            log.critical(f"an unexpected error occurred: {e}")
            sys.exit(1)

    def shutdown(self):
        """
        prints final statistics upon shutdown and exits the application gracefully.
        ensures all collected data is displayed.
        """
        print("\n" + "="*80)
        log.critical(">> dnsnetguard shutting down...")
        with self.lock:
            log.info(f"total packets processed: {self.stats['processed']:,}")
            log.info(f"packets allowed: {self.stats['allowed']:,}")
            if self.block_mode:
                log.warning(f"domains blocked: {self.stats['blocked']:,}")
            else:
                log.error(f"suspicious detections: {self.stats['detected']:,}")
        print("="*80)
        sys.exit(0)


def main():
    """
    main entry point of the dnsnetguard application.
    parses command-line arguments and initiates the packet interception.
    """
    parser = argparse.ArgumentParser(
        description="advanced network interceptor for detecting and blocking spyware, malware, and adware.",
        epilog="run with administrator privileges. use -b to actively block traffic. "
               "use -v for verbose output including allowed traffic."
    )
    # argument to enable blocking mode.
    parser.add_argument(
        '-b', '--block',
        action='store_true',
        help="enable block mode. if not set, dnsnetguard runs in monitor-only mode."
    )
    # argument to enable verbose logging.
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help="enable verbose mode. shows all allowed dns and tls traffic, "
             "in addition to blocked/detected entries."
    )
    args = parser.parse_args()

    # initializes the packetinterceptor with the parsed arguments.
    interceptor = PacketInterceptor(block_mode=args.block, verbose=args.verbose)
    # starts the interception process.
    interceptor.run()


# ensures main() is called only when the script is executed directly.
if __name__ == "__main__":
    main()
