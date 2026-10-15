package certificates

import (
	"strings"
	"testing"
)

func TestParseTargetAcceptsIntegralFloatPort(t *testing.T) {
	got, err := ParseTarget([]byte(`{"ip":"192.0.2.10","port":443.0}`))
	if err != nil || got.Port != 443 {
		t.Fatalf("443.0 rejected: %+v %v", got, err)
	}
}

func TestParseTargetRejectsNonIntegralAndBoolPorts(t *testing.T) {
	for _, line := range []string{
		`{"ip":"192.0.2.10","port":443.5}`,
		`{"ip":"192.0.2.10","port":true}`,
		`{"ip":"192.0.2.10","port":"443.5"}`,
	} {
		if _, err := ParseTarget([]byte(line)); err == nil {
			t.Fatalf("accepted %s", line)
		}
	}
}

func TestParseTargetMissingFieldErrors(t *testing.T) {
	if _, err := ParseTarget([]byte(`{"ip":"192.0.2.10"}`)); err == nil || !strings.Contains(err.Error(), `missing required field "port"`) {
		t.Fatalf("missing port error: %v", err)
	}
	if _, err := ParseTarget([]byte(`{"ip":"192.0.2.10","port":null}`)); err == nil || !strings.Contains(err.Error(), `missing required field "port"`) {
		t.Fatalf("null port error: %v", err)
	}
	if _, err := ParseTarget([]byte(`{"port":443}`)); err == nil || !strings.Contains(err.Error(), `missing required field "ip"`) {
		t.Fatalf("missing ip error: %v", err)
	}
	if _, err := ParseTarget([]byte(`{"ip":"","port":443}`)); err == nil || !strings.Contains(err.Error(), `missing required field "ip"`) {
		t.Fatalf("empty ip error: %v", err)
	}
}

func TestMinTLSVersionValidation(t *testing.T) {
	o := DefaultOptions()
	if o.MinTLSVersion != "1.2" {
		t.Fatalf("default min TLS version = %q, want 1.2", o.MinTLSVersion)
	}
	o.MinTLSVersion = "1.9"
	if err := o.Validate(); err == nil {
		t.Fatal("accepted unknown TLS version")
	}
	o.MinTLSVersion = ""
	if err := o.Validate(); err != nil {
		t.Fatalf("empty min TLS version rejected: %v", err)
	}
	o.MinTLSVersion = "1.3"
	if err := o.Validate(); err != nil {
		t.Fatalf("TLS 1.3 rejected: %v", err)
	}
	o.ExpiryWithinDays = -1
	if err := o.Validate(); err == nil {
		t.Fatal("accepted negative expiry window")
	}
}
