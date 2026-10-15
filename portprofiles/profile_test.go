package portprofiles

import (
	"encoding/json"
	"os/exec"
	"reflect"
	"testing"
)

func TestExposureProfileAndPythonAgree(t *testing.T) {
	want := []int{2375, 10250, 6443, 445, 3389, 5985, 5986, 5900, 22, 6379, 27017, 9200, 1433, 5432, 3306, 443, 8443, 80, 8080, 21}
	got, err := Ports("exposure20")
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("default profile: %v (%v)", got, err)
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable for cross-language check")
	}
	output, err := exec.Command(python, "-c", "import sys,json;sys.path.insert(0,'../tools');import random_targets;print(json.dumps(random_targets.profile_ports('exposure20')))").Output()
	if err != nil {
		t.Fatal(err)
	}
	var other []int
	if err := json.Unmarshal(output, &other); err != nil || !reflect.DeepEqual(got, other) {
		t.Fatalf("Python profile differs: %s (%v)", output, err)
	}
	got[0] = 1
	again, _ := Ports("exposure20")
	if again[0] != 2375 {
		t.Fatal("caller changed shared profile")
	}
}

func TestProtocolHintsAndCertificateProfile(t *testing.T) {
	for port, mode := range map[int]string{2375: "tcp", 10250: "tls", 6443: "tls", 445: "tcp", 3389: "tcp", 5985: "tcp", 5986: "tls", 5900: "tcp", 22: "tcp", 6379: "tcp", 27017: "tcp", 9200: "tcp", 1433: "tcp", 5432: "tcp", 3306: "tcp", 443: "tls", 8443: "tls", 80: "tcp", 8080: "tcp", 21: "ftp"} {
		hint, ok := Lookup(port)
		if !ok || hint.Mode != mode || hint.ServiceHint == "" || hint.ReviewOrder < 1 || hint.ReviewOrder > 20 {
			t.Fatalf("bad collector hint for %d: %+v", port, hint)
		}
	}
	if _, ok := Lookup(65000); ok {
		t.Fatal("unknown port identified as a service")
	}
	ports, err := Ports("certificates")
	if err != nil || !reflect.DeepEqual(ports, []int{443, 587, 21, 465, 993, 995, 8443}) {
		t.Fatalf("legacy profile: %v %v", ports, err)
	}
	if _, err := Ports("typo"); err == nil {
		t.Fatal("accepted unknown profile")
	}
}
