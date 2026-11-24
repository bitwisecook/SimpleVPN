// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
// A temporary loopback SSH server with a point-to-point channel in place of a kernel TUN device.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
)

func run() error {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return err
	}
	conf := &ssh.ServerConfig{PasswordCallback: func(c ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
		if c.User() != "fixture" || string(p) != "fixture-secret" {
			return nil, fmt.Errorf("denied")
		}
		return nil, nil
	}}
	conf.AddHostKey(signer)
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer l.Close()
	fmt.Printf("%d %x\n", l.Addr().(*net.TCPAddr).Port, sha256.Sum256(signer.PublicKey().Marshal()))
	c, err := l.Accept()
	if err != nil {
		return err
	}
	defer c.Close()
	_, ch, requests, err := ssh.NewServerConn(c, conf)
	if len(os.Args) > 1 && os.Args[1] == "wrongpin" {
		if err == nil {
			return fmt.Errorf("unverified peer reached authentication")
		}
		return nil
	}
	if err != nil {
		return err
	}
	go ssh.DiscardRequests(requests)
	next, ok := <-ch
	if !ok {
		return io.EOF
	}
	open := next.ExtraData()
	if next.ChannelType() != "tun@openssh.com" || len(open) != 8 || binary.BigEndian.Uint32(open) != 1 || binary.BigEndian.Uint32(open[4:]) != 7 {
		return fmt.Errorf("wrong channel request %q %x", next.ChannelType(), open)
	}
	if len(os.Args) > 1 && os.Args[1] == "denied" {
		return next.Reject(ssh.Prohibited, "PermitTunnel refused")
	}
	d, reqs, err := next.Accept()
	if err != nil {
		return err
	}
	defer d.Close()
	go ssh.DiscardRequests(reqs)
	malformed := []byte{0, 0, 0, 2, 0x45, 0, 0, 255}
	if _, err = d.Write(malformed); err != nil {
		return err
	}
	for i, family := range []byte{2, 24, 2, 24} {
		n, ver := 28, byte(0x45)
		if family == 24 {
			n, ver = 48, 0x60
		}
		frame := make([]byte, n+4)
		frame[3] = family
		frame[4] = ver
		if family == 2 {
			binary.BigEndian.PutUint16(frame[6:], uint16(n))
			frame[12] = 64
			frame[13] = 17
		} else {
			binary.BigEndian.PutUint16(frame[8:], uint16(n-40))
			frame[10] = 17
			frame[11] = 64
		}
		frame[len(frame)-1] = byte(i + 1)
		got := make([]byte, len(frame))
		if _, err = io.ReadFull(d, got); err != nil {
			return err
		}
		if !bytes.Equal(got, frame) {
			return fmt.Errorf("raw framing differs: %x", got)
		}
		if _, err = d.Write(frame); err != nil {
			return err
		}
	}
	return d.CloseWrite()
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
