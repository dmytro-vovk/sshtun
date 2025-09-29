package sshtun

import (
	"context"
	"errors"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type Tunnel struct {
	client *ssh.Client
	// config    *ssh.ClientConfig
	agent     agent.ExtendedAgent
	agentConn net.Conn
	address   string
	user      string
	password  string
	pk        []byte
	pkPath    string
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

func (t *Tunnel) Dial(ctx context.Context, addr string) (net.Conn, error) {
	config, err := t.buildConfig()
	if err != nil {
		return nil, err
	}

	t.client, err = ssh.Dial("tcp", t.address, config)
	if err != nil {
		return nil, err
	}

	return t.client.DialContext(ctx, "tcp", addr)
}

func (t *Tunnel) Close() error {
	var err error
	if t.agent != nil {
		err = t.agentConn.Close()
	}

	if t.client != nil {
		err = errors.Join(err, t.client.Close())
	}

	return err
}

func (t *Tunnel) buildConfig() (*ssh.ClientConfig, error) {
	config := &ssh.ClientConfig{
		User:            t.user,
		Auth:            []ssh.AuthMethod{},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	if t.password != "" {
		config.Auth = append(config.Auth, ssh.PasswordCallback(func() (string, error) {
			return t.password, nil
		}))
	}

	if t.pk != nil {
		signer, err := ssh.ParsePrivateKey(t.pk)
		if err != nil {
			return nil, err
		}
		config.Auth = append(config.Auth, ssh.PublicKeys(signer))
	}

	if t.pkPath != "" {
		pk, err := os.ReadFile(os.ExpandEnv(t.pkPath))
		if err != nil {
			return nil, err
		}

		signer, err := ssh.ParsePrivateKey(pk)
		if err != nil {
			return nil, err
		}

		config.Auth = append(config.Auth, ssh.PublicKeys(signer))
	}

	var err error
	if t.agentConn, err = net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
		config.Auth = append(config.Auth, ssh.PublicKeysCallback(agent.NewClient(t.agentConn).Signers))
	}

	return config, nil
}
