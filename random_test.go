package ip4scout

import (
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestRandomSeedDeterminism(t *testing.T) {
	digest := func(seed int64) string {
		cmd := RandomCommand{Seed: seed}
		if err := cmd.prepareBlacklist(); err != nil {
			t.Fatal(err)
		}
		ips, err := cmd.RandomPublicIPs(50)
		if err != nil {
			t.Fatal(err)
		}
		strs := make([]string, len(ips))
		for i, ip := range ips {
			strs[i] = ip.String()
		}
		sort.Strings(strs)
		return fmt.Sprintf("%x", md5.Sum([]byte(strings.Join(strs, "\n"))))
	}
	if digest(42) != digest(42) {
		t.Fatal("same seed produced different IP sets")
	}
	if digest(42) == digest(43) {
		t.Fatal("different seeds produced identical IP sets")
	}
}

func TestRandomPublicIPsDistinct(t *testing.T) {
	cmd := RandomCommand{Seed: 7, Distinct: true}
	if err := cmd.prepareBlacklist(); err != nil {
		t.Fatal(err)
	}
	ips, err := cmd.RandomPublicIPs(200)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool, len(ips))
	for _, ip := range ips {
		if seen[ip.String()] {
			t.Fatalf("duplicate address %s with Distinct set", ip)
		}
		seen[ip.String()] = true
	}
	if _, err := cmd.RandomPublicIPs(-1); err == nil {
		t.Fatal("accepted negative count")
	}
	if _, err := cmd.RandomPublicIPs(0); err != nil {
		t.Fatal(err)
	}
}

func TestRandomPublicIpIPv6(t *testing.T) {
	cmd := RandomCommand{IPv6: true}
	if err := cmd.prepareBlacklist(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		ip, err := cmd.RandomPublicIp()
		if err != nil {
			t.Fatal(err)
		}
		if ip.To4() != nil {
			t.Fatalf("IPv6 mode sampled IPv4 address %s", ip)
		}
		if !cmd.IsIpPublic(ip) {
			t.Fatalf("sampled non-public IPv6 address %s", ip)
		}
	}
	for _, value := range []string{"::1", "fe80::1", "fc00::1", "ff02::1", "2001:db8::1"} {
		if cmd.IsIpPublic(net.ParseIP(value)) {
			t.Errorf("non-global IPv6 address %s accepted as public", value)
		}
	}
	if !cmd.IsIpPublic(net.ParseIP("2606:4700:4700::1111")) {
		t.Error("global IPv6 address rejected")
	}
	v4only := RandomCommand{}
	if v4only.IsIpPublic(net.ParseIP("2606:4700:4700::1111")) {
		t.Error("IPv6 address accepted with IPv6 disabled")
	}
}

func TestExclusionsParseIPv6(t *testing.T) {
	set, err := parseExclusions(strings.NewReader("2001:db8::/32\n2001:db8:1::5\n2001:db8:2::1-2001:db8:2::9\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"2001:db8::1", "2001:db8:1::5", "2001:db8:2::1", "2001:db8:2::9"} {
		if !set.contains(net.ParseIP(value)) {
			t.Errorf("missing excluded IPv6 %s", value)
		}
	}
	for _, value := range []string{"2001:db9::1", "2001:db9:2::a", "2001:db7:1::4"} {
		if set.contains(net.ParseIP(value)) {
			t.Errorf("excluded adjacent IPv6 %s", value)
		}
	}
}

func TestExclusionSetMergesAdjacentIPv6(t *testing.T) {
	set, err := parseExclusions(strings.NewReader("2001:db8::/127\n2001:db8::2/127\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(set.v6Ranges) != 1 || set.v6Ranges[0].first.String() != "2001:db8::" || set.v6Ranges[0].last.String() != "2001:db8::3" {
		t.Fatalf("adjacent IPv6 ranges not merged: %+v", set.v6Ranges)
	}
}

func TestAddressAtV6SelectsRemainingSpace(t *testing.T) {
	set, err := parseExclusions(strings.NewReader("::1-::ffff\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := set.addressAtV6(big.NewInt(0)).String(); got != "::" {
		t.Fatalf("rank 0 = %s, want ::", got)
	}
	if got := set.addressAtV6(big.NewInt(1)).String(); got != "::1:0" {
		t.Fatalf("rank 1 = %s, want ::1:0", got)
	}
}

func TestAddBlockToBlacklistReturnsError(t *testing.T) {
	original := IPBlacklist
	defer func() { IPBlacklist = original }()
	cmd := RandomCommand{}
	if err := cmd.AddBLockToBlacklist("203.0.113.0/24"); err != nil {
		t.Fatal(err)
	}
	if err := cmd.AddBLockToBlacklist("not-a-cidr"); err == nil {
		t.Fatal("accepted invalid blacklist CIDR")
	}
	if cmd.IsIpPublic(net.ParseIP("203.0.113.5")) {
		t.Fatal("added blacklist entry ignored")
	}
}

func TestWaitForReplies(t *testing.T) {
	// Grace period is honoured: replies arriving during the wait are not lost.
	start := time.Now()
	if err := waitForReplies(context.Background(), make(chan error, 1), 150*time.Millisecond); err != nil {
		t.Fatalf("grace wait returned error: %v", err)
	}
	if elapsed := time.Since(start); elapsed < 150*time.Millisecond {
		t.Fatalf("returned after %v, want >= 150ms", elapsed)
	}
	// Listener error returns immediately, without waiting out the grace.
	want := errors.New("listener failed")
	errCh := make(chan error, 1)
	errCh <- want
	if err := waitForReplies(context.Background(), errCh, 10*time.Second); !errors.Is(err, want) {
		t.Fatalf("got %v, want %v", err, want)
	}
	// Cancelled context returns promptly.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := waitForReplies(ctx, make(chan error, 1), 10*time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context.Canceled", err)
	}
	// Zero grace returns immediately.
	start = time.Now()
	if err := waitForReplies(context.Background(), make(chan error, 1), 0); err != nil {
		t.Fatalf("zero grace returned error: %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("zero grace took %v, want immediate return", elapsed)
	}
}

func TestSendPacketRejectsIPv6(t *testing.T) {
	cmd := RandomCommand{}
	err := cmd.SendPacket(nil, nil, nil, nil, net.ParseIP("2001:db8::1"), 443)
	if err == nil || !strings.Contains(err.Error(), "IPv6") {
		t.Fatalf("expected IPv6 emission error, got %v", err)
	}
}
