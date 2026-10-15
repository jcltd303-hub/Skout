package certificates

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestCLIChild(t *testing.T) {
	if os.Getenv("SCOUT_CLI_TEST_CHILD") != "1" {
		return
	}
	os.Exit(Main(nil))
}

func TestCLIBlockedOutputCancellation(t *testing.T) {
	for _, secondInterrupt := range []bool{false, true} {
		label := "first_interrupt"
		if secondInterrupt {
			label = "second_interrupt"
		}
		t.Run(label, func(t *testing.T) {
			child := exec.Command(os.Args[0], "-test.run=^TestCLIChild$")
			child.Env = append(os.Environ(), "SCOUT_CLI_TEST_CHILD=1", "GORACE=atexit_sleep_ms=0")
			child.Stdin = strings.NewReader(strings.Repeat("{broken\n", 10000))
			var stderr bytes.Buffer
			child.Stderr = &stderr
			out, err := child.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			defer out.Close()
			if err = child.Start(); err != nil {
				t.Fatal(err)
			}
			defer child.Process.Kill()
			ready := make([]byte, 1)
			if _, err = out.Read(ready); err != nil {
				t.Fatal(err)
			}
			// Fill the pipe, then stop reading it as a stalled downstream consumer would.
			time.Sleep(100 * time.Millisecond)
			done := make(chan error, 1)
			go func() { done <- child.Wait() }()
			start := time.Now()
			if err = child.Process.Signal(os.Interrupt); err != nil {
				t.Fatal(err)
			}
			limit := 3 * time.Second
			if secondInterrupt {
				time.Sleep(100 * time.Millisecond)
				_ = child.Process.Signal(os.Interrupt)
				limit = time.Second
			}
			select {
			case err = <-done:
				var exit *exec.ExitError
				if !errors.As(err, &exit) {
					t.Fatalf("expected cancelled exit: %v", err)
				}
				if !secondInterrupt && exit.ExitCode() != 130 {
					t.Fatalf("exit=%d stderr=%s", exit.ExitCode(), stderr.String())
				}
				if time.Since(start) > limit {
					t.Fatal("cancellation exceeded deadline")
				}
			case <-time.After(limit):
				_ = child.Process.Kill()
				<-done
				t.Fatal("blocked stdout prevented process cancellation")
			}
		})
	}
}
