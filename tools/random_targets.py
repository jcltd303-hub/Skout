#!/usr/bin/env python3
"""Emit random IPv4/IPv6 endpoint JSON with shared port profiles and masscan exclusions."""

import argparse
import bisect
import ipaddress
import json
from pathlib import Path
import random
import signal
import sys


DEFAULT_EXCLUSIONS = Path(__file__).resolve().parents[1] / "data" / "masscan-exclude.conf"
PORT_PROFILE = Path(__file__).resolve().parents[1] / "portprofiles" / "exposure20.json"
# Match the native scanner's mandatory exclusions, including multicast/reserved.
MANDATORY_EXCLUSIONS = """0.0.0.0/8
10.0.0.0/8
100.64.0.0/10
127.0.0.0/8
172.16.0.0/12
192.168.0.0/16
224.0.0.0/3
"""
# Mandatory IPv6 exclusions (Batch 1 parity): loopback, link-local, ULA,
# multicast, and the documentation prefix.
MANDATORY_V6_EXCLUSIONS = """::1/128
fe80::/10
fc00::/7
ff00::/8
2001:db8::/32
"""
MAX_IPV4 = (1 << 32) - 1
MAX_IPV6 = (1 << 128) - 1


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


class ExclusionsV6:
    """IPv6 counterpart of Exclusions: merged ranges over the 128-bit space."""

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
        if cursor <= MAX_IPV6:
            self.allowed.append((cursor, MAX_IPV6))
            total += MAX_IPV6 - cursor + 1
            self.cumulative.append(total)
        self.available = total

    @classmethod
    def from_text(cls, text):
        ranges = []
        for line_number, raw in enumerate(text.splitlines(), 1):
            value = raw.partition("#")[0].strip()
            if not value:
                continue
            if ":" not in value:
                # IPv4 entry: not applicable to the IPv6 pool, skip it.
                continue
            try:
                if "-" in value:
                    first, last = (int(ipaddress.IPv6Address(part.strip())) for part in value.split("-"))
                    if first > last:
                        raise ValueError("range start exceeds range end")
                elif "/" in value:
                    prefix = value.split("/")[1]
                    if not prefix.isascii() or not prefix.isdigit() or (len(prefix) > 1 and prefix.startswith("0")):
                        raise ValueError("CIDR prefix must be a number from 0 to 128")
                    network = ipaddress.IPv6Network(value, strict=False)
                    first, last = int(network.network_address), int(network.broadcast_address)
                else:
                    first = last = int(ipaddress.IPv6Address(value))
            except ValueError as error:
                raise ValueError(f"line {line_number}: invalid IPv6 exclusion {value!r}: {error}") from error
            ranges.append((first, last))
        return cls(ranges)

    def contains(self, address):
        value = int(ipaddress.IPv6Address(address))
        index = bisect.bisect_right(self.starts, value) - 1
        return index >= 0 and value <= self.ranges[index][1]

    def random_address(self, rng):
        if not self.available:
            raise ValueError("exclusions leave no IPv6 targets")
        rank = rng.randrange(self.available)
        index = bisect.bisect_right(self.cumulative, rank)
        previous = self.cumulative[index - 1] if index else 0
        return ipaddress.IPv6Address(self.allowed[index][0] + rank - previous)


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


def load_exclusions_v6(extra_files=()):
    ranges = list(ExclusionsV6.from_text(MANDATORY_V6_EXCLUSIONS).ranges)
    for path in (DEFAULT_EXCLUSIONS, *map(Path, extra_files)):
        try:
            ranges.extend(ExclusionsV6.from_text(path.read_text(encoding="utf-8")).ranges)
        except ValueError as error:
            raise ValueError(f"{path}: {error}") from error
    exclusions = ExclusionsV6(ranges)
    if not exclusions.available:
        raise ValueError("exclusions leave no IPv6 targets")
    return exclusions


def profile_ports(name):
    doc = json.loads(PORT_PROFILE.read_text(encoding="utf-8"))
    if name == "exposure20":
        values = [row["port"] for row in doc["ports"]]
        if len(values) != 20 or len(set(values)) != 20:
            raise ValueError("exposure20 must contain 20 unique ports")
    elif name == "certificates":
        values = doc["certificate_ports"]
    else:
        raise ValueError("unknown port profile; use exposure20 or certificates")
    if not values or any(type(port) is not int or not 1 <= port <= 65535 for port in values):
        raise ValueError("invalid bundled port profile")
    return tuple(values)


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


def generate_targets(count, ports, exclusions, rng=None, family="4", distinct=False,
                      exclusions_v6=None):
    """Yield ``count`` samples, one endpoint per port per sample.

    ``family`` is "4", "6", or "both". For "both", ``exclusions`` is the IPv4
    pool and ``exclusions_v6`` the IPv6 pool; the family is picked per sample
    with ``rng``. For "6", ``exclusions`` is the IPv6 pool unless
    ``exclusions_v6`` is given. When ``distinct`` is true, (ip, port) pairs
    never repeat; a request for more distinct pairs than the chosen pool(s)
    hold raises before anything is emitted.
    """
    if count < 0:
        raise ValueError("count must be nonnegative")
    if not ports or any(not isinstance(port, int) or not 1 <= port <= 65535 for port in ports):
        raise ValueError("ports must be integers from 1 to 65535")
    if family not in ("4", "6", "both"):
        raise ValueError("family must be '4', '6' or 'both'")
    if family == "4":
        pools = [exclusions]
    elif family == "6":
        pools = [exclusions_v6 if exclusions_v6 is not None else exclusions]
    else:
        if exclusions is None or exclusions_v6 is None:
            raise ValueError("family 'both' requires IPv4 and IPv6 exclusions")
        pools = [exclusions, exclusions_v6]
    for pool in pools:
        if not pool.available:
            label = "IPv6" if isinstance(pool, ExclusionsV6) else "IPv4"
            raise ValueError(f"exclusions leave no {label} targets")
    if distinct and count > sum(pool.available for pool in pools):
        raise ValueError("distinct targets requested exceed available address space")
    rng = rng or random.SystemRandom()
    seen = set()
    for _ in range(count):
        while True:
            pool = pools[0] if len(pools) == 1 else pools[rng.randrange(len(pools))]
            address = str(pool.random_address(rng))
            if not distinct or all((address, port) not in seen for port in ports):
                break
        for port in ports:
            seen.add((address, port))
            yield {"ip": address, "port": port}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=1000, help="Number of samples; one endpoint per port per sample")
    parser.add_argument("--ports", "-p", help="Comma-separated ports; overrides --port-profile")
    parser.add_argument("--port-profile", choices=("exposure20", "certificates"), default="exposure20", help="Default: exposure20; certificates selects the original TLS/upgrade profile")
    parser.add_argument("--list-ports", action="store_true", help="Print selected ports and exit without generating endpoints")
    parser.add_argument("--excludefile", "-b", type=Path, action="append", default=[], help="Additional masscan-format exclusion file; may be repeated")
    parser.add_argument("--seed", type=int, default=None, help="Seed the RNG for deterministic output; default uses system randomness")
    parser.add_argument("--family", choices=("4", "6", "both"), default=None, help="Address family: 4 (default), 6, or both")
    parser.add_argument("--ipv6", action="store_true", help="Sample IPv6 targets (shorthand for --family 6)")
    parser.add_argument("--distinct", dest="distinct", action="store_true", default=True, help="Emit distinct (ip, port) pairs (default)")
    parser.add_argument("--no-distinct", dest="distinct", action="store_false", help="Allow duplicate (ip, port) pairs")
    args = parser.parse_args(argv)
    family = args.family or ("6" if args.ipv6 else "4")
    try:
        if args.count < 0:
            raise ValueError("count must be nonnegative")
        ports = parse_ports(args.ports) if args.ports is not None else profile_ports(args.port_profile)
        if args.list_ports:
            print(",".join(map(str, ports)))
            return 0
        if family == "4":
            exclusions = load_exclusions(args.excludefile)
            exclusions_v6 = None
        elif family == "6":
            exclusions = load_exclusions_v6(args.excludefile)
            exclusions_v6 = None
        else:
            exclusions = load_exclusions(args.excludefile)
            exclusions_v6 = load_exclusions_v6(args.excludefile)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    rng = random.Random(args.seed) if args.seed is not None else random.SystemRandom()
    try:
        for endpoint in generate_targets(args.count, ports, exclusions, rng=rng,
                                         family=family, distinct=args.distinct,
                                         exclusions_v6=exclusions_v6):
            print(json.dumps(endpoint), flush=True)
    except KeyboardInterrupt:
        return 130
    except ValueError as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    if hasattr(signal, "SIGPIPE"):
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    raise SystemExit(main())
