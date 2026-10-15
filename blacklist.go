package ip4scout

import (
	"bufio"
	_ "embed"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
)

//go:embed data/masscan-exclude.conf
var masscanExclusionText string

var masscanExclusions, masscanExclusionError = parseExclusions(strings.NewReader(masscanExclusionText))

type ipv4Range struct {
	first uint32
	last  uint32
}

type ipv6Range struct {
	first netip.Addr
	last  netip.Addr
}

// parsedExclusion is one exclusion entry, either IPv4 or IPv6.
type parsedExclusion struct {
	isV6 bool
	v4   ipv4Range
	v6   ipv6Range
}

type exclusionSet struct {
	ranges      []ipv4Range
	v6Ranges    []ipv6Range
	available   uint64
	availableV6 *big.Int
}

func newExclusionSet(v4 []ipv4Range, v6 []ipv6Range) exclusionSet {
	ordered := append([]ipv4Range(nil), v4...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].first == ordered[j].first {
			return ordered[i].last < ordered[j].last
		}
		return ordered[i].first < ordered[j].first
	})
	merged := make([]ipv4Range, 0, len(ordered))
	for _, current := range ordered {
		if len(merged) == 0 || uint64(current.first) > uint64(merged[len(merged)-1].last)+1 {
			merged = append(merged, current)
		} else if current.last > merged[len(merged)-1].last {
			merged[len(merged)-1].last = current.last
		}
	}
	available := uint64(1) << 32
	for _, blocked := range merged {
		available -= uint64(blocked.last) - uint64(blocked.first) + 1
	}

	orderedV6 := append([]ipv6Range(nil), v6...)
	sort.Slice(orderedV6, func(i, j int) bool {
		if c := orderedV6[i].first.Compare(orderedV6[j].first); c != 0 {
			return c < 0
		}
		return orderedV6[i].last.Compare(orderedV6[j].last) < 0
	})
	mergedV6 := make([]ipv6Range, 0, len(orderedV6))
	for _, current := range orderedV6 {
		if len(mergedV6) == 0 {
			mergedV6 = append(mergedV6, current)
			continue
		}
		prev := &mergedV6[len(mergedV6)-1]
		// Merge when current starts at or before one past the previous end.
		next := prev.last.Next()
		if !next.IsValid() || current.first.Compare(next) <= 0 {
			if current.last.Compare(prev.last) > 0 {
				prev.last = current.last
			}
			continue
		}
		mergedV6 = append(mergedV6, current)
	}
	availableV6 := new(big.Int).Lsh(big.NewInt(1), 128)
	for _, blocked := range mergedV6 {
		span := new(big.Int).Sub(addrToBig(blocked.last), addrToBig(blocked.first))
		span.Add(span, big.NewInt(1))
		availableV6.Sub(availableV6, span)
	}
	return exclusionSet{ranges: merged, v6Ranges: mergedV6, available: available, availableV6: availableV6}
}

func addrToBig(addr netip.Addr) *big.Int {
	bytes := addr.As16()
	return new(big.Int).SetBytes(bytes[:])
}

func bigToAddr(value *big.Int) netip.Addr {
	var bytes [16]byte
	value.FillBytes(bytes[:])
	addr, _ := netip.AddrFromSlice(bytes[:])
	return addr
}

func parseExclusions(reader io.Reader) (exclusionSet, error) {
	var v4 []ipv4Range
	var v6 []ipv6Range
	scanner := bufio.NewScanner(reader)
	line := 0
	for scanner.Scan() {
		line++
		text := strings.TrimSpace(strings.SplitN(scanner.Text(), "#", 2)[0])
		if text == "" {
			continue
		}
		blocked, err := parseExclusion(text)
		if err != nil {
			return exclusionSet{}, fmt.Errorf("line %d: %w", line, err)
		}
		if blocked.isV6 {
			v6 = append(v6, blocked.v6)
		} else {
			v4 = append(v4, blocked.v4)
		}
	}
	if err := scanner.Err(); err != nil {
		return exclusionSet{}, fmt.Errorf("read exclusions: %w", err)
	}
	return newExclusionSet(v4, v6), nil
}

// parseExclusion accepts a single address, a CIDR, or an inclusive range
// (first-last) in either address family. A ':' in the text selects the IPv6
// path; IPv6 addresses never contain '-', so range splitting is unambiguous.
func parseExclusion(text string) (parsedExclusion, error) {
	if strings.Contains(text, ":") {
		return parseExclusionV6(text)
	}
	address := func(value string) (uint32, error) {
		ip, err := netip.ParseAddr(strings.TrimSpace(value))
		if err != nil || !ip.Is4() {
			return 0, fmt.Errorf("invalid IPv4 address %q", value)
		}
		bytes := ip.As4()
		return binary.BigEndian.Uint32(bytes[:]), nil
	}
	if strings.Contains(text, "-") {
		parts := strings.Split(text, "-")
		if len(parts) != 2 {
			return parsedExclusion{}, fmt.Errorf("invalid IPv4 range %q", text)
		}
		first, err := address(parts[0])
		if err != nil {
			return parsedExclusion{}, err
		}
		last, err := address(parts[1])
		if err != nil {
			return parsedExclusion{}, err
		}
		if first > last {
			return parsedExclusion{}, fmt.Errorf("reversed IPv4 range %q", text)
		}
		return parsedExclusion{v4: ipv4Range{first, last}}, nil
	}
	if strings.Contains(text, "/") {
		prefix, err := netip.ParsePrefix(text)
		if err != nil || !prefix.Addr().Is4() {
			return parsedExclusion{}, fmt.Errorf("invalid IPv4 CIDR %q", text)
		}
		bytes := prefix.Masked().Addr().As4()
		first := binary.BigEndian.Uint32(bytes[:])
		last := uint64(first) + (uint64(1) << (32 - prefix.Bits())) - 1
		return parsedExclusion{v4: ipv4Range{first, uint32(last)}}, nil
	}
	value, err := address(text)
	return parsedExclusion{v4: ipv4Range{value, value}}, err
}

func parseExclusionV6(text string) (parsedExclusion, error) {
	address := func(value string) (netip.Addr, error) {
		ip, err := netip.ParseAddr(strings.TrimSpace(value))
		if err != nil || ip.Is4() {
			return netip.Addr{}, fmt.Errorf("invalid IPv6 address %q", value)
		}
		return ip, nil
	}
	if strings.Contains(text, "-") {
		parts := strings.Split(text, "-")
		if len(parts) != 2 {
			return parsedExclusion{}, fmt.Errorf("invalid IPv6 range %q", text)
		}
		first, err := address(parts[0])
		if err != nil {
			return parsedExclusion{}, err
		}
		last, err := address(parts[1])
		if err != nil {
			return parsedExclusion{}, err
		}
		if first.Compare(last) > 0 {
			return parsedExclusion{}, fmt.Errorf("reversed IPv6 range %q", text)
		}
		return parsedExclusion{isV6: true, v6: ipv6Range{first, last}}, nil
	}
	if strings.Contains(text, "/") {
		prefix, err := netip.ParsePrefix(text)
		if err != nil || prefix.Addr().Is4() {
			return parsedExclusion{}, fmt.Errorf("invalid IPv6 CIDR %q", text)
		}
		first := prefix.Masked().Addr()
		last := new(big.Int).Add(addrToBig(first), new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(128-prefix.Bits())), big.NewInt(1)))
		return parsedExclusion{isV6: true, v6: ipv6Range{first, bigToAddr(last)}}, nil
	}
	value, err := address(text)
	return parsedExclusion{isV6: true, v6: ipv6Range{value, value}}, err
}

func (set exclusionSet) contains(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		value := binary.BigEndian.Uint32(v4)
		index := sort.Search(len(set.ranges), func(i int) bool { return set.ranges[i].last >= value })
		return index < len(set.ranges) && set.ranges[index].first <= value
	}
	v6 := ip.To16()
	if v6 == nil {
		return false
	}
	addr, _ := netip.AddrFromSlice(v6)
	index := sort.Search(len(set.v6Ranges), func(i int) bool { return set.v6Ranges[i].last.Compare(addr) >= 0 })
	return index < len(set.v6Ranges) && set.v6Ranges[index].first.Compare(addr) <= 0
}

// addressAt selects an allowed IPv4 address by its rank in the remaining space.
// It avoids an unbounded rejection loop when a custom file excludes most IPs.
func (set exclusionSet) addressAt(rank uint64) net.IP {
	if rank >= set.available {
		panic("IPv4 rank outside available target space")
	}
	var cursor uint64
	for _, blocked := range set.ranges {
		gap := uint64(blocked.first) - cursor
		if rank < gap {
			return ipv4FromUint(uint32(cursor + rank))
		}
		rank -= gap
		cursor = uint64(blocked.last) + 1
	}
	return ipv4FromUint(uint32(cursor + rank))
}

// addressAtV6 selects an allowed IPv6 address by its rank in the remaining
// space, mirroring addressAt for the 128-bit space.
func (set exclusionSet) addressAtV6(rank *big.Int) net.IP {
	if rank == nil || rank.Sign() < 0 || rank.Cmp(set.availableV6) >= 0 {
		panic("IPv6 rank outside available target space")
	}
	remaining := new(big.Int).Set(rank)
	cursor := netip.AddrFrom16([16]byte{})
	for _, blocked := range set.v6Ranges {
		gap := new(big.Int).Sub(addrToBig(blocked.first), addrToBig(cursor))
		if remaining.Cmp(gap) < 0 {
			return net.IP(bigToAddr(new(big.Int).Add(addrToBig(cursor), remaining)).AsSlice())
		}
		remaining.Sub(remaining, gap)
		next := blocked.last.Next()
		if !next.IsValid() {
			// No address space remains past this range; remaining must be 0
			// here because rank < availableV6, so this is unreachable.
			panic("IPv6 rank outside available target space")
		}
		cursor = next
	}
	return net.IP(bigToAddr(new(big.Int).Add(addrToBig(cursor), remaining)).AsSlice())
}

func ipv4FromUint(value uint32) net.IP {
	return net.IPv4(byte(value>>24), byte(value>>16), byte(value>>8), byte(value))
}

// mandatoryV6Exclusions covers the non-global IPv6 space. It backs IsIpPublic
// for IPv6 targets when no exclusion set has been prepared yet.
var mandatoryV6Exclusions = func() exclusionSet {
	set, err := parseExclusions(strings.NewReader(strings.Join(mandatoryV6Networks, "\n") + "\n"))
	if err != nil {
		panic(err)
	}
	return set
}()

var mandatoryV6Networks = []string{
	"::1/128",
	"fe80::/10",
	"fc00::/7",
	"ff00::/8",
	"2001:db8::/32",
}

func (cmd *RandomCommand) prepareBlacklist() error {
	var ranges []ipv4Range
	var v6Ranges []ipv6Range
	for _, network := range IPBlacklist {
		if network == nil || network.IP.To4() == nil {
			continue
		}
		bits, size := network.Mask.Size()
		if size != 32 {
			return fmt.Errorf("invalid mandatory IPv4 blacklist mask")
		}
		blocked, err := parseExclusion(fmt.Sprintf("%s/%d", network.IP.To4(), bits))
		if err != nil {
			return err
		}
		ranges = append(ranges, blocked.v4)
	}
	if !cmd.DisableRecommended {
		if masscanExclusionError != nil {
			return fmt.Errorf("bundled masscan exclusions: %w", masscanExclusionError)
		}
		ranges = append(ranges, masscanExclusions.ranges...)
		v6Ranges = append(v6Ranges, masscanExclusions.v6Ranges...)
	}
	for _, file := range []*os.File{cmd.BlacklistFile, cmd.ExcludeFile} {
		if file == nil {
			continue
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			return fmt.Errorf("exclusions %s: %w", file.Name(), err)
		}
		custom, err := parseExclusions(file)
		if err != nil {
			return fmt.Errorf("exclusions %s: %w", file.Name(), err)
		}
		ranges = append(ranges, custom.ranges...)
		v6Ranges = append(v6Ranges, custom.v6Ranges...)
	}
	if cmd.IPv6 {
		for _, network := range mandatoryV6Networks {
			blocked, err := parseExclusion(network)
			if err != nil {
				return err
			}
			v6Ranges = append(v6Ranges, blocked.v6)
		}
	}
	set := newExclusionSet(ranges, v6Ranges)
	if set.available == 0 {
		return fmt.Errorf("exclusions leave no IPv4 targets")
	}
	if cmd.IPv6 && (set.availableV6 == nil || set.availableV6.Sign() <= 0) {
		return fmt.Errorf("exclusions leave no IPv6 targets")
	}
	cmd.exclusions = &set
	return nil
}
