package ip4scout

import (
	"bufio"
	_ "embed"
	"encoding/binary"
	"fmt"
	"io"
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

type exclusionSet struct {
	ranges    []ipv4Range
	available uint64
}

func newExclusionSet(ranges []ipv4Range) exclusionSet {
	ordered := append([]ipv4Range(nil), ranges...)
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
	return exclusionSet{ranges: merged, available: available}
}

func parseExclusions(reader io.Reader) (exclusionSet, error) {
	var ranges []ipv4Range
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
		ranges = append(ranges, blocked)
	}
	if err := scanner.Err(); err != nil {
		return exclusionSet{}, fmt.Errorf("read exclusions: %w", err)
	}
	return newExclusionSet(ranges), nil
}

func parseExclusion(text string) (ipv4Range, error) {
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
			return ipv4Range{}, fmt.Errorf("invalid IPv4 range %q", text)
		}
		first, err := address(parts[0])
		if err != nil {
			return ipv4Range{}, err
		}
		last, err := address(parts[1])
		if err != nil {
			return ipv4Range{}, err
		}
		if first > last {
			return ipv4Range{}, fmt.Errorf("reversed IPv4 range %q", text)
		}
		return ipv4Range{first, last}, nil
	}
	if strings.Contains(text, "/") {
		prefix, err := netip.ParsePrefix(text)
		if err != nil || !prefix.Addr().Is4() {
			return ipv4Range{}, fmt.Errorf("invalid IPv4 CIDR %q", text)
		}
		bytes := prefix.Masked().Addr().As4()
		first := binary.BigEndian.Uint32(bytes[:])
		last := uint64(first) + (uint64(1) << (32 - prefix.Bits())) - 1
		return ipv4Range{first, uint32(last)}, nil
	}
	value, err := address(text)
	return ipv4Range{value, value}, err
}

func (set exclusionSet) contains(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	value := binary.BigEndian.Uint32(v4)
	index := sort.Search(len(set.ranges), func(i int) bool { return set.ranges[i].last >= value })
	return index < len(set.ranges) && set.ranges[index].first <= value
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

func ipv4FromUint(value uint32) net.IP {
	return net.IPv4(byte(value>>24), byte(value>>16), byte(value>>8), byte(value))
}

func (cmd *RandomCommand) prepareBlacklist() error {
	var ranges []ipv4Range
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
		ranges = append(ranges, blocked)
	}
	if !cmd.DisableRecommended {
		if masscanExclusionError != nil {
			return fmt.Errorf("bundled masscan exclusions: %w", masscanExclusionError)
		}
		ranges = append(ranges, masscanExclusions.ranges...)
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
	}
	set := newExclusionSet(ranges)
	if set.available == 0 {
		return fmt.Errorf("exclusions leave no IPv4 targets")
	}
	cmd.exclusions = &set
	return nil
}
