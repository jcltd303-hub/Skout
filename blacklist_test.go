package ip4scout

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/alecthomas/kong"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestNativeParserAcceptsMasscanExclusionFlag(t *testing.T) {
	for _, flag := range []string{"--excludefile", "--blacklist-file", "-b"} {
		file := exclusionFile(t, "8.8.8.8\n")
		var app struct {
			Random RandomCommand `cmd:""`
		}
		parser, err := kong.New(&app)
		if err != nil {
			t.Fatal(err)
		}
		ctx, err := parser.Parse([]string{"random", flag, file.Name(), "-r", "0", "-p", "443"})
		if err != nil {
			t.Errorf("flag %s: %v", flag, err)
			continue
		}
		if app.Random.BlacklistFile != nil {
			t.Cleanup(func() { app.Random.BlacklistFile.Close() })
		}
		if app.Random.ExcludeFile != nil {
			t.Cleanup(func() { app.Random.ExcludeFile.Close() })
		}
		if err := ctx.Run(); err == nil || !strings.Contains(err.Error(), "rate-limit must be positive") {
			t.Errorf("flag %s did not reach pre-network validation: %v", flag, err)
		}
	}
}

func TestGoAndTermuxExclusionPoliciesMatch(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("cross-language check requires Python 3")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	code := "import sys,json; sys.path.insert(0,'tools'); import random_targets; s=random_targets.load_exclusions(); print(json.dumps({'ranges':s.ranges,'available':s.available}))"
	output, err := exec.CommandContext(ctx, python, "-c", code).CombinedOutput()
	if err != nil {
		t.Fatalf("Python exclusions: %v: %s", err, output)
	}
	var pythonSet struct {
		Ranges    [][2]uint32 `json:"ranges"`
		Available uint64      `json:"available"`
	}
	if err := json.Unmarshal(output, &pythonSet); err != nil {
		t.Fatal(err)
	}
	cmd := RandomCommand{}
	if err := cmd.prepareBlacklist(); err != nil {
		t.Fatal(err)
	}
	if pythonSet.Available != cmd.exclusions.available || len(pythonSet.Ranges) != len(cmd.exclusions.ranges) {
		t.Fatalf("different policies: Python allows %d addresses over %d exclusions; Go allows %d over %d", pythonSet.Available, len(pythonSet.Ranges), cmd.exclusions.available, len(cmd.exclusions.ranges))
	}
	for i, blocked := range cmd.exclusions.ranges {
		if pythonSet.Ranges[i] != [2]uint32{blocked.first, blocked.last} {
			t.Fatalf("different exclusion interval at %d", i)
		}
	}
}

func TestAllowedAddressRanksHandleIPv4Extremes(t *testing.T) {
	set, err := parseExclusions(strings.NewReader("0.0.0.1-255.255.255.254\n"))
	if err != nil {
		t.Fatal(err)
	}
	if set.available != 2 || set.addressAt(0).String() != "0.0.0.0" || set.addressAt(1).String() != "255.255.255.255" {
		t.Fatal("IPv4 bounds overflowed while selecting the remaining addresses")
	}
}

func TestMasscanSnapshotContainsEveryPinnedEntry(t *testing.T) {
	var entries []string
	for _, line := range strings.Split(masscanExclusionText, "\n") {
		value := strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if value != "" {
			entries = append(entries, value)
		}
	}
	if len(entries) != 332 {
		t.Fatalf("got %d source entries, want 332", len(entries))
	}
	got := fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(entries, "\n")+"\n")))
	if got != "17b9d7e2ad8bf25cd6ed35d77e6ad2313e923b54b3fda529ca3c797b00ccfcd0" {
		t.Fatalf("pinned masscan active entries differ: %s", got)
	}
}

func TestRandomDefaultMasscanExclusions(t *testing.T) {
	cmd := RandomCommand{}
	for _, value := range []string{
		"153.11.0.0", "153.11.255.255", "8.12.162.0", "8.12.164.255",
		"146.82.55.93", "194.77.40.242", "194.77.40.246", "205.1.2.3",
		"129.123.0.1", "132.206.123.1", "193.60.0.1", "169.254.1.1",
		"198.18.0.1", "192.0.2.1", "224.0.0.1", "255.255.255.255",
	} {
		if cmd.IsIpPublic(net.ParseIP(value)) {
			t.Errorf("masscan-excluded address %s was accepted", value)
		}
	}
	for _, value := range []string{
		"1.1.1.1", "8.8.8.8", "8.12.161.255", "8.12.165.0",
		"146.82.55.92", "146.82.55.94", "194.77.40.243", "104.16.0.1",
	} {
		if !cmd.IsIpPublic(net.ParseIP(value)) {
			t.Errorf("unlisted public address %s was rejected", value)
		}
	}
}

func TestExclusionsParseMasscanFormatsAndBoundaries(t *testing.T) {
	set, err := parseExclusions(strings.NewReader("# comment\n8.8.8.9/24 # masked CIDR\n9.9.9.9\n11.0.0.2 - 11.0.0.4\n\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"8.8.8.0", "8.8.8.255", "9.9.9.9", "11.0.0.2", "11.0.0.4"} {
		if !set.contains(net.ParseIP(value)) {
			t.Errorf("missing excluded boundary %s", value)
		}
	}
	for _, value := range []string{"8.8.7.255", "8.8.9.0", "9.9.9.8", "9.9.9.10", "11.0.0.1", "11.0.0.5"} {
		if set.contains(net.ParseIP(value)) {
			t.Errorf("excluded adjacent address %s", value)
		}
	}
}

type brokenBlacklistReader struct{}

func (brokenBlacklistReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

func TestExclusionsRejectMalformedAndUnreadableFiles(t *testing.T) {
	for _, value := range []string{"bad", "1.1.1.1/33", "1.1.1.1/032", "1.1.1.1/00", "::1", "::/0", "1.1.1.3-1.1.1.2", "1.1.1.1-", "1.1.1.1-2.2.2.2-3.3.3.3"} {
		if _, err := parseExclusions(strings.NewReader("# heading\n" + value)); err == nil || !strings.Contains(err.Error(), "line 2") {
			t.Errorf("invalid entry %q should report line 2, got %v", value, err)
		}
	}
	if _, err := parseExclusions(brokenBlacklistReader{}); err == nil || !strings.Contains(err.Error(), "read failed") {
		t.Fatalf("lost read error: %v", err)
	}
}

func exclusionFile(t *testing.T, content string) *os.File {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "exclude-*.conf")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { file.Close() })
	if _, err := io.WriteString(file, content); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	return file
}

func TestRandomCustomExclusionsStayLocalAndAddToDefaults(t *testing.T) {
	cmd := RandomCommand{BlacklistFile: exclusionFile(t, "# custom\n8.8.8.8\n"), ExcludeFile: exclusionFile(t, "1.1.1.1-1.1.1.3\n")}
	if err := cmd.prepareBlacklist(); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"8.8.8.8", "1.1.1.1", "1.1.1.3", "153.11.1.1"} {
		if cmd.IsIpPublic(net.ParseIP(value)) {
			t.Errorf("custom/default exclusion missed %s", value)
		}
	}
	fresh := RandomCommand{}
	if !fresh.IsIpPublic(net.ParseIP("8.8.8.8")) {
		t.Fatal("custom exclusions leaked to another command")
	}
	disabled := RandomCommand{DisableRecommended: true}
	if !disabled.IsIpPublic(net.ParseIP("153.11.1.1")) || disabled.IsIpPublic(net.ParseIP("10.0.0.1")) {
		t.Fatal("disable-recommended must retain mandatory private exclusions")
	}
}

func TestRandomRejectsBadExclusionsBeforeNetworkSetup(t *testing.T) {
	for _, content := range []string{"8.8.8.8\ninvalid\n", "0.0.0.0/0\n", "0.0.0.0-127.255.255.255\n128.0.0.0-255.255.255.255\n"} {
		cmd := RandomCommand{RateLimit: 1, Ports: "443", BlacklistFile: exclusionFile(t, content)}
		if err := cmd.Run(); err == nil {
			t.Errorf("accepted unusable exclusion file %q", content)
		}
	}
	file := exclusionFile(t, "8.8.8.8\n")
	file.Close()
	cmd := RandomCommand{RateLimit: 1, Ports: "443", BlacklistFile: file}
	if err := cmd.Run(); err == nil {
		t.Fatal("accepted unreadable exclusions")
	}
}

func TestRandomSamplesRemainingAddressesWithoutRejectionLoop(t *testing.T) {
	cmd := RandomCommand{BlacklistFile: exclusionFile(t, "0.0.0.0-8.8.8.7\n8.8.8.10-255.255.255.255\n")}
	if err := cmd.prepareBlacklist(); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		ip := cmd.RandomPublicIp().String()
		if ip != "8.8.8.8" && ip != "8.8.8.9" {
			t.Fatalf("sampled excluded address %s", ip)
		}
		seen[ip] = true
	}
	if len(seen) != 2 {
		t.Fatalf("failed to sample both available addresses: %v", seen)
	}
	if cmd.IsIpPublic(nil) || cmd.IsIpPublic(net.ParseIP("::1")) {
		t.Fatal("accepted non-IPv4 target")
	}
}
