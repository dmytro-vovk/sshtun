package sshtun

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

func newTestTunnel(t *testing.T, server *testSSHServer) *Tunnel {
	t.Helper()

	// Ensure buildConfig does not pick up a real ssh-agent.
	t.Setenv("SSH_AUTH_SOCK", "")

	tun := New(server.Addr(), testUser, testPassword)

	t.Cleanup(func() { _ = tun.Close() })

	return tun
}

// TestDialConcurrent verifies that concurrent Dial calls through one Tunnel
// are safe (no data race, no cross-connection interference). This is the
// production shape: the Tunnel is registered as the global MySQL dialer and
// is hit concurrently by independent goroutines.
func TestDialConcurrent(t *testing.T) {
	server := newTestSSHServer(t)
	echo := newEchoServer(t)
	tun := newTestTunnel(t, server)

	const goroutines = 8

	var wg sync.WaitGroup

	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)

		go func(n int) {
			defer wg.Done()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			conn, err := tun.Dial(ctx, echo)
			if err != nil {
				errs <- fmt.Errorf("goroutine %d: dial: %w", n, err)

				return
			}

			defer func() { _ = conn.Close() }()

			if err := echoRoundTrip(conn, fmt.Sprintf("hello-%d", n)); err != nil {
				errs <- fmt.Errorf("goroutine %d: roundtrip: %w", n, err)
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}
}

// TestDialDoesNotKillExistingConnections is the regression test for the prod
// incident: a second Dial must not tear down connections opened by a previous
// Dial (the old implementation closed the shared ssh.Client on every call).
func TestDialDoesNotKillExistingConnections(t *testing.T) {
	server := newTestSSHServer(t)
	echo := newEchoServer(t)
	tun := newTestTunnel(t, server)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn1, err := tun.Dial(ctx, echo)
	if err != nil {
		t.Fatalf("dial conn1: %v", err)
	}

	defer func() { _ = conn1.Close() }()

	if err := echoRoundTrip(conn1, "before"); err != nil {
		t.Fatalf("conn1 roundtrip before second dial: %v", err)
	}

	conn2, err := tun.Dial(ctx, echo)
	if err != nil {
		t.Fatalf("dial conn2: %v", err)
	}

	defer func() { _ = conn2.Close() }()

	// conn1 must still be alive after conn2 was dialled.
	if err := echoRoundTrip(conn1, "after"); err != nil {
		t.Fatalf("conn1 died after second dial (mutual-kill regression): %v", err)
	}

	if err := echoRoundTrip(conn2, "conn2"); err != nil {
		t.Fatalf("conn2 roundtrip: %v", err)
	}
}

// TestDialReusesSSHClient verifies that sequential Dials share one SSH
// transport (one handshake) instead of re-dialling SSH per call.
func TestDialReusesSSHClient(t *testing.T) {
	server := newTestSSHServer(t)
	echo := newEchoServer(t)
	tun := newTestTunnel(t, server)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for i := 0; i < 3; i++ {
		conn, err := tun.Dial(ctx, echo)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}

		if err := echoRoundTrip(conn, "ping"); err != nil {
			t.Fatalf("roundtrip %d: %v", i, err)
		}

		_ = conn.Close()
	}

	if got := server.handshakes.Load(); got != 1 {
		t.Fatalf("expected 1 SSH handshake for 3 dials, got %d", got)
	}
}

// TestDialReconnectsAfterTransportDrop verifies that when the SSH transport
// dies (NAT drop, server restart), the next Dial transparently re-establishes
// the tunnel instead of failing forever.
func TestDialReconnectsAfterTransportDrop(t *testing.T) {
	server := newTestSSHServer(t)
	echo := newEchoServer(t)
	tun := newTestTunnel(t, server)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn1, err := tun.Dial(ctx, echo)
	if err != nil {
		t.Fatalf("dial conn1: %v", err)
	}

	_ = conn1.Close()

	// Simulate the NAT/firewall cutting the transport.
	server.dropConnections()

	// Give the client a moment to observe the close.
	time.Sleep(100 * time.Millisecond)

	conn2, err := tun.Dial(ctx, echo)
	if err != nil {
		t.Fatalf("dial conn2 after transport drop: %v", err)
	}

	defer func() { _ = conn2.Close() }()

	if err := echoRoundTrip(conn2, "recovered"); err != nil {
		t.Fatalf("roundtrip after reconnect: %v", err)
	}

	if got := server.handshakes.Load(); got != 2 {
		t.Fatalf("expected 2 handshakes (initial + reconnect), got %d", got)
	}
}

// TestKeepalive verifies the Tunnel sends periodic keepalive requests so
// NAT/firewall state on the path does not expire between uses.
func TestKeepalive(t *testing.T) {
	server := newTestSSHServer(t)
	echo := newEchoServer(t)

	t.Setenv("SSH_AUTH_SOCK", "")

	tun := New(server.Addr(), testUser, testPassword).WithKeepalive(50 * time.Millisecond)

	t.Cleanup(func() { _ = tun.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := tun.Dial(ctx, echo)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	defer func() { _ = conn.Close() }()

	deadline := time.After(3 * time.Second)

	for server.keepalives.Load() < 2 {
		select {
		case <-deadline:
			t.Fatalf("expected >=2 keepalives, got %d", server.keepalives.Load())
		case <-time.After(20 * time.Millisecond):
		}
	}
}
