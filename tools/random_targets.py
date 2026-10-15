#!/usr/bin/env python3
"""Emit random IPv4 endpoint JSON while honoring the bundled masscan exclusions."""

import argparse
import bisect
import ipaddress
import json
from pathlib import Path
import random
import signal
import sys


DEFAULT_EXCLUSIONS = Path(__file__).resolve().parents[1] / "data" / "masscan-exclude.conf"
# Match the native scanner's mandatory exclusions, including multicast/reserved.
MANDATORY_EXCLUSIONS = """0.0.0.0/8
10.0.0.0/8
100.64.0.0/10
127.0.0.0/8
172.16.0.0/12
192.168.0.0/16
224.0.0.0/3
"""
MAX_IPV4 = (1 << 32) - 1


class Exclusions:
    def __init__(self, ranges):
        merged = []
        for first, last in sorted(ranges):
            if not merged or first > merged[-1][1] + 1:
                merged.append((first, last))
            elif last > merged[-1][1]:
                merged[-1] = (merged[-1][0], last)
        self.ranges = tuple(merged)
        self.starts = tuple(first for first, _ in merged)
        self.allowed = []
        self.cumulative = []
        cursor = 0
        total = 0
        for first, last in merged:
            if cursor < first:
                self.allowed.append((cursor, first - 1))
                total += first - cursor
                self.cumulative.append(total)
            cursor = last + 1
        if cursor <= MAX_IPV4:
            self.allowed.append((cursor, MAX_IPV4))
            total += MAX_IPV4 - cursor + 1
            self.cumulative.append(total)
        self.available = total

    @classmethod
    def from_text(cls, text):
        ranges = []
        for line_number, raw in enumerate(text.splitlines(), 1):
            value = raw.partition("#")[0].strip()
            if not value:
                continue
            try:
                if "-" in value:
                    first, last = (int(ipaddress.IPv4Address(part.strip())) for part in value.split("-"))
                    if first > last:
                        raise ValueError("range start exceeds range end")
                elif "/" in value:
                    prefix = value.split("/")[1]
                    if not prefix.isascii() or not prefix.isdigit() or (len(prefix) > 1 and prefix.startswith("0")):
                        raise ValueError("CIDR prefix must be a number from 0 to 32")
                    network = ipaddress.IPv4Network(value, strict=False)
                    first, last = int(network.network_address), int(network.broadcast_address)
                else:
                    first = last = int(ipaddress.IPv4Address(value))
            except ValueError as error:
                raise ValueError(f"line {line_number}: invalid IPv4 exclusion {value!r}: {error}") from error
            ranges.append((first, last))
        return cls(ranges)

    def contains(self, address):
        value = int(ipaddress.IPv4Address(address))
        index = bisect.bisect_right(self.starts, value) - 1
        return index >= 0 and value <= self.ranges[index][1]

    def random_address(self, rng):
        if not self.available:
            raise ValueError("exclusions leave no IPv4 targets")
        rank = rng.randrange(self.available)
        index = bisect.bisect_right(self.cumulative, rank)
        previous = self.cumulative[index - 1] if index else 0
        return ipaddress.IPv4Address(self.allowed[index][0] + rank - previous)


def load_exclusions(extra_files=()):
    ranges = list(Exclusions.from_text(MANDATORY_EXCLUSIONS).ranges)
    for path in (DEFAULT_EXCLUSIONS, *map(Path, extra_files)):
        try:
            ranges.extend(Exclusions.from_text(path.read_text(encoding="utf-8")).ranges)
        except ValueError as error:
            raise ValueError(f"{path}: {error}") from error
    exclusions = Exclusions(ranges)
    if not exclusions.available:
        raise ValueError("exclusions leave no IPv4 targets")
    return exclusions


def parse_ports(text):
    ports = []
    for part in text.split(","):
        token = part.strip()
        if not token.isascii() or not token.isdigit() or not 1 <= int(token) <= 65535:
            raise ValueError("ports must be comma-separated integers from 1 to 65535")
        port = int(token)
        if port not in ports:
            ports.append(port)
    return tuple(ports)


def generate_targets(count, ports, exclusions, rng=None):
    if count < 0:
        raise ValueError("count must be nonnegative")
    if not ports or any(not isinstance(port, int) or not 1 <= port <= 65535 for port in ports):
        raise ValueError("ports must be integers from 1 to 65535")
    if not exclusions.available:
        raise ValueError("exclusions leave no IPv4 targets")
    rng = rng or random.SystemRandom()
    for _ in range(count):
        address = str(exclusions.random_address(rng))
        for port in ports:
            yield {"ip": address, "port": port}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=1000, help="Number of IPv4 samples; one endpoint per port per sample")
    parser.add_argument("--ports", default="443,587,21", help="Comma-separated ports (default: 443,587,21)")
    parser.add_argument("--excludefile", "-b", type=Path, action="append", default=[], help="Additional masscan-format exclusion file; may be repeated")
    args = parser.parse_args(argv)
    try:
        if args.count < 0:
            raise ValueError("count must be nonnegative")
        ports = parse_ports(args.ports)
        exclusions = load_exclusions(args.excludefile)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    try:
        for endpoint in generate_targets(args.count, ports, exclusions):
            print(json.dumps(endpoint), flush=True)
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    if hasattr(signal, "SIGPIPE"):
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    raise SystemExit(main())
