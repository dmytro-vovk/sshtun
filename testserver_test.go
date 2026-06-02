package sshtun

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"
)

const (
	testUser     = "test"
	testPassword = "secret"
)

// testSSHServer is a minimal in-process SSH server that supports password
// auth, direct-tcpip channel forwarding, and counts handshakes + keepalive
// global requests. It is just enough server to exercise Tunnel end-to-end.
type testSSHServer struct {
	listener   net.Listener
	config     *ssh.ServerConfig
	handshakes atomic.Int64
	keepalives atomic.Int64

	mu    sync.Mutex
	conns []*ssh.ServerConn
	done  chan struct{}
}

func newTestSSHServer(t *testing.T) *testSSHServer {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("host key signer: %v", err)
	}

	config := &ssh.ServerConfig{
		PasswordCallback: func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if meta.User() == testUser && string(password) == testPassword {
				return nil, nil
			}

			return nil, errors.New("auth failed")
		},
	}
	config.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	s := &testSSHServer{
		listener: listener,
		config:   config,
		done:     make(chan struct{}),
	}

	go s.acceptLoop()

	t.Cleanup(s.Close)

	return s
}

func (s *testSSHServer) Addr() string { return s.listener.Addr().String() }

func (s *testSSHServer) Close() {
	select {
	case <-s.done:
		return
	default:
		close(s.done)
	}

	_ = s.listener.Close()
	s.dropConnections()
}

// dropConnections force-closes all live SSH server connections, simulating a
// NAT/firewall cutting the transport.
func (s *testSSHServer) dropConnections() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, c := range s.conns {
		_ = c.Close()
	}

	s.conns = nil
}

func (s *testSSHServer) acceptLoop() {
	for {
		raw, err := s.listener.Accept()
		if err != nil {
			return
		}

		go s.handleConn(raw)
	}
}

func (s *testSSHServer) handleConn(raw net.Conn) {
	conn, chans, reqs, err := ssh.NewServerConn(raw, s.config)
	if err != nil {
		_ = raw.Close()

		return
	}

	s.handshakes.Add(1)

	s.mu.Lock()
	s.conns = append(s.conns, conn)
	s.mu.Unlock()

	go func() {
		for req := range reqs {
			if req.Type == "keepalive@openssh.com" {
				s.keepalives.Add(1)
			}

			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		}
	}()

	for newChan := range chans {
		if newChan.ChannelType() != "direct-tcpip" {
			_ = newChan.Reject(ssh.UnknownChannelType, "unsupported")

			continue
		}

		go s.handleDirectTCPIP(newChan)
	}
}

// directTCPIPMsg is the extra data payload of a direct-tcpip channel open
// request (RFC 4254 §7.2).
type directTCPIPMsg struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

func (s *testSSHServer) handleDirectTCPIP(newChan ssh.NewChannel) {
	var msg directTCPIPMsg
	if err := ssh.Unmarshal(newChan.ExtraData(), &msg); err != nil {
		_ = newChan.Reject(ssh.Prohibited, "bad payload")

		return
	}

	target, err := net.Dial("tcp", net.JoinHostPort(msg.DestAddr, itoa(msg.DestPort)))
	if err != nil {
		_ = newChan.Reject(ssh.ConnectionFailed, err.Error())

		return
	}

	ch, reqs, err := newChan.Accept()
	if err != nil {
		_ = target.Close()

		return
	}

	go ssh.DiscardRequests(reqs)

	go func() {
		defer func() { _ = ch.Close(); _ = target.Close() }()
		_, _ = io.Copy(ch, target)
	}()

	go func() {
		_, _ = io.Copy(target, ch)
	}()
}

func itoa(v uint32) string {
	return strconv.Itoa(int(v))
}

// newEchoServer starts a TCP echo server and returns its address.
func newEchoServer(t *testing.T) string {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}

			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	t.Cleanup(func() { _ = l.Close() })

	return l.Addr().String()
}

// echoRoundTrip writes msg and expects it echoed back.
func echoRoundTrip(conn net.Conn, msg string) error {
	if _, err := conn.Write([]byte(msg)); err != nil {
		return err
	}

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}

	if string(buf) != msg {
		return errors.New("echo mismatch")
	}

	return nil
}
