package ip4scout

import (
	"reflect"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/google/gopacket/layers"
)

func TestNativeProfileDefaultsAndExplicitOverride(t *testing.T) {
	cmd := RandomCommand{}
	if err := cmd.preparePorts(); err != nil || len(cmd.ports) != 20 || cmd.ports[0] != 2375 {
		t.Fatalf("default: %v (%v)", cmd.ports, err)
	}
	cmd = RandomCommand{PortProfile: "exposure20", Ports: "443,22"}
	if err := cmd.preparePorts(); err != nil || !reflect.DeepEqual(cmd.ports, []layers.TCPPort{22, 443}) {
		t.Fatalf("explicit ports ignored: %v (%v)", cmd.ports, err)
	}
	cmd = RandomCommand{CertificateProfile: true}
	if err := cmd.preparePorts(); err != nil || len(cmd.ports) != 7 {
		t.Fatalf("legacy flag: %v (%v)", cmd.ports, err)
	}
	cmd = RandomCommand{PortProfile: "typo", Ports: "443"}
	if err := cmd.preparePorts(); err == nil {
		t.Fatal("accepted unknown profile")
	}
	var app struct {
		Random RandomCommand `cmd:""`
	}
	parser, err := kong.New(&app)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parser.Parse([]string{"random", "--port-profile=certificates", "--list-ports"}); err != nil {
		t.Fatal(err)
	}
	if !app.Random.ListPorts || app.Random.PortProfile != "certificates" {
		t.Fatalf("flags not wired: %+v", app.Random)
	}
}
