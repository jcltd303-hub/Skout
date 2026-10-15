package ip4scout

import (
	"github.com/google/gopacket/layers"
	"reflect"
	"testing"
)

func TestPortsAreSortedUnique(t *testing.T) {
	got, err := ParsePortsList("587,443,21,443,993-995")
	want := []layers.TCPPort{21, 443, 587, 993, 994, 995}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v (%v), want %v", got, err, want)
	}
}

func TestPortsRejectWrappedAndEmptyValues(t *testing.T) {
	for _, value := range []string{"0", "-1", "65536", "1-65536", "0-1", "443,", "", "4-2", "1-2-3"} {
		if _, err := ParsePortsList(value); err == nil {
			t.Fatalf("accepted invalid ports %q", value)
		}
	}
}

func TestRandomRejectsNonpositiveRateBeforeNetworkSetup(t *testing.T) {
	for _, rate := range []int{0, -1} {
		cmd := RandomCommand{RateLimit: rate}
		if err := cmd.Run(); err == nil {
			t.Fatalf("accepted packet rate %d", rate)
		}
	}
}
