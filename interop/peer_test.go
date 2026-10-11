// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// image is the reference peer's image, built from ./peer.
const image = "sigma-enip-interop:cpppo-5.2.5"

// envVar turns the tests on.
const envVar = "SIGMA_ENIP_INTEROP"

// needDocker skips the test unless the environment variable is 1 and
// Docker answers, and builds the peer image.
func needDocker(t *testing.T) {
	t.Helper()
	if os.Getenv(envVar) != "1" {
		t.Skip("set " + envVar + "=1 to run the interop tests (needs Docker)")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("docker is not running")
	}
	// Built every time (Docker reuses its cached layers), so edits to the
	// peer are never tested against a stale image.
	out, err := exec.Command("docker", "build", "-q", "-t", image, "peer").CombinedOutput()
	if err != nil {
		t.Fatalf("docker build: %v\n%s", err, out)
	}
}

// freePort returns a port free for both TCP and UDP on the loopback
// interface.
func freePort(t *testing.T) int {
	t.Helper()
	for try := 0; try < 20; try++ {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		_ = ln.Close()
		if err == nil {
			_ = u.Close()
			return port
		}
	}
	t.Fatal("no port free for both TCP and UDP")
	return 0
}

// peer is a reference program running in a container; its output lines
// are collected.
type peer struct {
	t     *testing.T
	name  string
	cmd   *exec.Cmd
	stdin io.WriteCloser
	lines chan string

	mu  sync.Mutex
	log []string
}

// startPeer runs `docker run --rm -i --name <unique> <args...>`.
func startPeer(t *testing.T, args ...string) *peer {
	t.Helper()
	p := &peer{t: t, name: fmt.Sprintf("sigma-enip-%d", time.Now().UnixNano()), lines: make(chan string, 4096)}
	full := append([]string{"run", "--rm", "-i", "--name", p.name}, args...)
	p.cmd = exec.Command("docker", full...)
	var err error
	if p.stdin, err = p.cmd.StdinPipe(); err != nil {
		t.Fatal(err)
	}
	r, w := io.Pipe()
	p.cmd.Stdout, p.cmd.Stderr = w, w
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			line := sc.Text()
			p.mu.Lock()
			p.log = append(p.log, line)
			p.mu.Unlock()
			select {
			case p.lines <- line:
			default:
			}
		}
	}()
	go func() { _ = p.cmd.Wait(); _ = w.Close() }()
	t.Cleanup(func() {
		_ = p.stdin.Close()
		_ = exec.Command("docker", "stop", "-t", "2", p.name).Run()
		if t.Failed() || os.Getenv(envVar+"_LOG") == "1" {
			t.Logf("peer output:\n%s", p.output())
		}
	})
	return p
}

func (p *peer) output() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return strings.Join(p.log, "\n")
}

// expect waits for an output line containing all the parts, skipping
// others, and returns it.
func (p *peer) expect(within time.Duration, parts ...string) string {
	p.t.Helper()
	deadline := time.After(within)
	for {
		select {
		case l := <-p.lines:
			ok := true
			for _, part := range parts {
				if !strings.Contains(l, part) {
					ok = false
					break
				}
			}
			if ok {
				return l
			}
		case <-deadline:
			p.t.Fatalf("no peer line with %q within %s", parts, within)
			return ""
		}
	}
}
