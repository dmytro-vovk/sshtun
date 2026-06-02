// Package sshtun provides a concurrency-safe TCP dialer that forwards
// connections through a single shared SSH transport ("direct-tcpip"
// channels). It is designed to be registered as a custom dialer for database
// drivers (e.g. mysql.RegisterDialContext) whose connection pools dial
// concurrently.
package sshtun

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// defaultKeepaliveInterval is how often keepalive probes are sent when
// WithKeepalive was not called. Keepalives serve two purposes: they keep
// NAT/firewall conntrack state on the path alive, and they detect a dead
// transport early so the next Dial reconnects instead of timing out.
const defaultKeepaliveInterval = 30 * time.Second

// Tunnel dials TCP connections through one shared SSH client. All methods are
// safe for concurrent use: Dial calls are serialised internally, the SSH
// transport is reused across calls (one handshake, many channels), and a dead
// transport is re-established transparently on the next Dial.
type Tunnel struct {
	address   string
	user      string
	password  string
	pk        []byte
	pkPath    string
	keepalive time.Duration

	mu     sync.Mutex
	client *ssh.Client
	closed bool
}

// New creates an SSH tunnel with a username/password.
func New(address, user, password string) *Tunnel {
	return &Tunnel{
		address:  address,
		user:     user,
		password: password,
	}
}

// NewWithPK creates an SSH tunnel with a private key.
func NewWithPK(address, user string, pk []byte) *Tunnel {
	return &Tunnel{
		address: address,
		user:    user,
		pk:      pk,
	}
}

// NewWithPKPath creates an SSH tunnel with a path to a private key.
func NewWithPKPath(address, user, pkPath string) *Tunnel {
	return &Tunnel{
		address: address,
		user:    user,
		pkPath:  pkPath,
	}
}

// WithKeepalive sets the interval for SSH-level keepalive probes and returns
// the Tunnel for chaining. Call it before the first Dial; the value is read
// when the transport is established. Zero or negative restores the default.
func (t *Tunnel) WithKeepalive(interval time.Duration) *Tunnel {
	t.keepalive = interval

	return t
}

// Dial opens a TCP connection to addr through the SSH tunnel. The underlying
// SSH client is shared and reused: concurrent Dials are serialised, existing
// connections are never torn down by later Dials, and a transport-level
// failure triggers exactly one reconnect attempt within the same call.
func (t *Tunnel) Dial(ctx context.Context, addr string) (net.Conn, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil, errors.New("sshtun: tunnel is closed")
	}

	if t.client == nil {
		if err := t.connectLocked(ctx); err != nil {
			return nil, err
		}
	}

	conn, err := t.client.DialContext(ctx, "tcp", addr)
	if err == nil {
		return conn, nil
	}

	// The remote answered the channel-open with an explicit refusal (target
	// port closed, administratively prohibited, ...). The SSH transport
	// itself is healthy — reconnecting would not help. Surface the error.
	var openErr *ssh.OpenChannelError
	if errors.As(err, &openErr) {
		return nil, err
	}

	// Caller's context expired or was cancelled — not a transport fault.
	if ctx.Err() != nil {
		return nil, err
	}

	// Transport-level failure (silently dropped NAT path, server restart,
	// half-dead connection): drop the client and reconnect once.
	t.dropClientLocked()

	if cerr := t.connectLocked(ctx); cerr != nil {
		return nil, errors.Join(err, cerr)
	}

	return t.client.DialContext(ctx, "tcp", addr)
}

// Close shuts the tunnel down. Subsequent Dials fail.
func (t *Tunnel) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.closed = true

	var err error

	if t.client != nil {
		err = t.client.Close()
		t.client = nil
	}

	return err
}

// connectLocked establishes a fresh SSH client and starts its keepalive loop.
// Caller must hold t.mu.
func (t *Tunnel) connectLocked(ctx context.Context) error {
	config, cleanup, err := t.buildConfig()
	if err != nil {
		return err
	}

	// The ssh-agent connection (if any) is only needed during the handshake.
	defer cleanup()

	var dialer net.Dialer

	raw, err := dialer.DialContext(ctx, "tcp", t.address)
	if err != nil {
		return err
	}

	// Bound the SSH handshake by the caller's deadline, then clear it: the
	// transport is long-lived and must not inherit a per-call deadline.
	if deadline, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(deadline)
	}

	conn, chans, reqs, err := ssh.NewClientConn(raw, t.address, config)
	if err != nil {
		_ = raw.Close()

		return err
	}

	_ = raw.SetDeadline(time.Time{})

	client := ssh.NewClient(conn, chans, reqs)
	t.client = client

	go t.keepaliveLoop(client)

	return nil
}

// dropClientLocked closes and forgets the current client. Caller must hold t.mu.
func (t *Tunnel) dropClientLocked() {
	if t.client != nil {
		_ = t.client.Close()
		t.client = nil
	}
}

// forgetClient clears t.client if it still points at the given client, so the
// next Dial reconnects instead of reusing a dead transport. A no-op when the
// client was already replaced.
func (t *Tunnel) forgetClient(client *ssh.Client) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.client == client {
		t.client = nil
	}
}

// keepaliveLoop sends periodic keepalive probes on the given client and
// retires it from the Tunnel when the transport dies — whichever way death is
// observed first (probe failure or the transport closing underneath us).
func (t *Tunnel) keepaliveLoop(client *ssh.Client) {
	interval := t.keepalive
	if interval <= 0 {
		interval = defaultKeepaliveInterval
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	dead := make(chan struct{})

	go func() {
		_ = client.Wait() // returns when the transport closes, however that happens
		close(dead)
	}()

	for {
		select {
		case <-dead:
			t.forgetClient(client)

			return
		case <-ticker.C:
			if _, _, err := client.SendRequest("keepalive@openssh.com", true, nil); err != nil {
				_ = client.Close()
				t.forgetClient(client)

				return
			}
		}
	}
}

// buildConfig assembles the client config from the configured auth material.
// The returned cleanup closes the ssh-agent connection (if one was opened)
// and must be called once the handshake has completed.
func (t *Tunnel) buildConfig() (*ssh.ClientConfig, func(), error) {
	config := &ssh.ClientConfig{
		User:            t.user,
		Auth:            []ssh.AuthMethod{},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	cleanup := func() {}

	if t.password != "" {
		config.Auth = append(config.Auth, ssh.PasswordCallback(func() (string, error) {
			return t.password, nil
		}))
	}

	if t.pk != nil {
		signer, err := ssh.ParsePrivateKey(t.pk)
		if err != nil {
			return nil, nil, err
		}

		config.Auth = append(config.Auth, ssh.PublicKeys(signer))
	}

	if t.pkPath != "" {
		pk, err := os.ReadFile(os.ExpandEnv(t.pkPath))
		if err != nil {
			return nil, nil, err
		}

		signer, err := ssh.ParsePrivateKey(pk)
		if err != nil {
			return nil, nil, err
		}

		config.Auth = append(config.Auth, ssh.PublicKeys(signer))
	}

	if agentConn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
		config.Auth = append(config.Auth, ssh.PublicKeysCallback(agent.NewClient(agentConn).Signers))
		cleanup = func() { _ = agentConn.Close() }
	}

	return config, cleanup, nil
}
