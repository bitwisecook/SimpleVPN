// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//go:build darwin && cgo

// Package ocproxyrelay supervises OpenConnect's --script-tun userspace boundary.
package ocproxyrelay

/*
#include <stdlib.h>
#include <libproc.h>
#include <sys/proc_info.h>
#include <netinet/in.h>
#include <netinet/tcp_fsm.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
// Observe exit without reaping. The child's PID/PGID then remains reserved
// until the supervisor has shut down the entire forwarding process group.
static int child_exit(int pid){
    siginfo_t info;
    int r;
    do { r=waitid(P_PID,pid,&info,WEXITED|WNOWAIT); } while (r<0 && errno==EINTR);
    return !r && info.si_code==CLD_EXITED ? info.si_status : -1;
}
static int owns_listener(int pid,int parent,const char *path,int port) {
    struct proc_bsdinfo child;
    if(proc_pidinfo(pid,PROC_PIDTBSDINFO,0,&child,sizeof(child))!=sizeof(child)||child.pbi_ppid!=parent)return 0;
    char image[PROC_PIDPATHINFO_MAXSIZE];struct stat have,want;
    if(proc_pidpath(pid,image,sizeof(image))<=0||stat(image,&have)||stat(path,&want)||have.st_dev!=want.st_dev||have.st_ino!=want.st_ino)return 0;
    struct proc_fdinfo entries[256];
    int n=proc_pidinfo(pid,PROC_PIDLISTFDS,0,entries,sizeof(entries));
    for(int i=0;i<n/(int)sizeof(entries[0]);i++){
        if(entries[i].proc_fdtype!=PROX_FDTYPE_SOCKET)continue;
        struct socket_fdinfo info;
        if(proc_pidfdinfo(pid,entries[i].proc_fd,PROC_PIDFDSOCKETINFO,&info,sizeof(info))!=sizeof(info)||
           info.psi.soi_kind!=SOCKINFO_TCP||info.psi.soi_family!=AF_INET)continue;
        struct tcp_sockinfo *tcp=&info.psi.soi_proto.pri_tcp;
        if(tcp->tcpsi_state==TCPS_LISTEN && ntohs((uint16_t)tcp->tcpsi_ini.insi_lport)==port &&
           tcp->tcpsi_ini.insi_laddr.ina_46.i46a_addr4.s_addr==htonl(INADDR_LOOPBACK))return 1;
    }
    return 0;
}
*/
import "C"
import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"pxengine/packetrouter"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const adapter = "openconnect-proxy"
const controlFD = 3

type launch struct {
	Client     string `json:"client"`
	Proxy      string `json:"proxy"`
	Profile    string `json:"profile"`
	Kind       string `json:"kind"`
	Source     string `json:"source"`
	Nonce      string `json:"nonce"`
	Port       int    `json:"port"`
	AuthLength int    `json:"authLength"`
}

func socketPair() ([2]int, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		return fds, err
	}
	for _, fd := range fds {
		unix.CloseOnExec(fd)
		for _, opt := range []int{unix.SO_SNDBUF, unix.SO_RCVBUF} {
			if err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, opt, 256*1024); err != nil {
				unix.Close(fds[0])
				unix.Close(fds[1])
				return fds, err
			}
		}
	}
	return fds, nil
}
func rawDatagram(fd int) bool {
	kind, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	addr, e := unix.Getpeername(fd)
	_, ok := addr.(*unix.SockaddrUnix)
	return err == nil && kind == unix.SOCK_DGRAM && e == nil && ok
}
func ownFile(fd int, name string) *os.File { return os.NewFile(uintptr(fd), name) }
func channel(f *os.File) (*net.UnixConn, error) {
	c, err := net.FileConn(f)
	f.Close()
	if err != nil {
		return nil, err
	}
	u, ok := c.(*net.UnixConn)
	if !ok {
		c.Close()
		return nil, errors.New("expected local datagram socket")
	}
	return u, nil
}
func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
func readSettings(in io.Reader) (launch, error) {
	var size uint32
	var v launch
	if err := binary.Read(in, binary.BigEndian, &size); err != nil || size == 0 || size > 256<<10 {
		return v, errors.New("invalid private proxy configuration")
	}
	b := make([]byte, size)
	if _, err := io.ReadFull(in, b); err != nil {
		return v, err
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return v, errors.New("invalid private proxy configuration")
	}
	if !filepath.IsAbs(v.Client) || !filepath.IsAbs(v.Proxy) || v.Port < 1 || v.Port > 65535 || v.AuthLength < 0 || v.AuthLength > 1<<20 || len(v.Nonce) != 36 || strings.ContainsAny(v.Nonce, "\r\n ") {
		return v, errors.New("invalid proxy executable, port or session identity")
	}
	return v, nil
}
func Attach(proxy, portText string) error {
	n, err := strconv.Atoi(portText)
	if err != nil || n < 1 || n > 65535 || !filepath.IsAbs(proxy) {
		return errors.New("invalid ocproxy command")
	}
	vpn, err := strconv.Atoi(os.Getenv("VPNFD"))
	if err != nil || vpn <= controlFD || !rawDatagram(vpn) || !rawDatagram(controlFD) {
		return errors.New("OpenConnect did not supply its managed VPN datagram channel")
	}
	// OpenConnect starts its script in a separate group. Return to the owned
	// supervisor's client group so a scripted abort also terminates ocproxy.
	ppid := os.Getppid()
	group, e := unix.Getpgid(ppid)
	if e != nil || group != ppid || unix.Setpgid(0, group) != nil {
		return errors.New("OpenConnect script is outside the supervised process group")
	}
	pair, err := socketPair()
	if err != nil {
		return err
	}
	defer unix.Close(pair[0])
	defer unix.Close(pair[1])
	var life [2]int
	if err = unix.Pipe(life[:]); err != nil {
		return err
	}
	defer unix.Close(life[0])
	defer unix.Close(life[1])
	unix.CloseOnExec(life[0])
	unix.CloseOnExec(vpn)
	unix.CloseOnExec(controlFD)
	var pid [4]byte
	binary.BigEndian.PutUint32(pid[:], uint32(os.Getpid()))
	if _, err = unix.SendmsgN(controlFD, pid[:], unix.UnixRights(vpn, pair[0], life[0]), nil, 0); err != nil {
		return err
	}
	// Only the private peer channel and exit-notification writer survive exec.
	if _, err = unix.FcntlInt(uintptr(pair[1]), unix.F_SETFD, 0); err != nil {
		return err
	}
	os.Setenv("VPNFD", strconv.Itoa(pair[1]))
	return unix.Exec(proxy, []string{proxy, "-D", portText}, os.Environ())
}

type attachment struct {
	vpn, local *net.UnixConn
	life       *os.File
	pid        int
}

func (a *attachment) close() { a.vpn.Close(); a.local.Close(); a.life.Close() }
func receive(c *net.UnixConn) (*attachment, error) {
	var pid [4]byte
	oob := make([]byte, unix.CmsgSpace(3*4))
	n, no, flags, _, err := c.ReadMsgUnix(pid[:], oob)
	if err != nil {
		return nil, err
	}
	messages, err := unix.ParseSocketControlMessage(oob[:no])
	if err != nil {
		return nil, err
	}
	var fds []int
	for _, message := range messages {
		rights, e := unix.ParseUnixRights(&message)
		if e == nil {
			fds = append(fds, rights...)
		}
	}
	defer func() {
		for _, fd := range fds {
			if fd >= 0 {
				unix.Close(fd)
			}
		}
	}()
	if n != 4 || flags&(unix.MSG_CTRUNC|unix.MSG_TRUNC) != 0 || len(fds) != 3 || !rawDatagram(fds[0]) || !rawDatagram(fds[1]) {
		return nil, errors.New("invalid managed OpenConnect channels")
	}
	for _, fd := range fds {
		unix.CloseOnExec(fd)
	}
	vpn, e := channel(ownFile(fds[0], "VPN"))
	fds[0] = -1
	if e != nil {
		return nil, e
	}
	local, e := channel(ownFile(fds[1], "SOCKS"))
	fds[1] = -1
	if e != nil {
		vpn.Close()
		return nil, e
	}
	if err = unix.SetNonblock(fds[2], true); err != nil {
		vpn.Close()
		local.Close()
		return nil, err
	}
	life := ownFile(fds[2], "ocproxy lifetime")
	fds[2] = -1
	return &attachment{vpn, local, life, int(binary.BigEndian.Uint32(pid[:]))}, nil
}

// OpenConnect's script-tun descriptor carries exactly one unprefixed IP datagram.
func completeIP(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	switch b[0] >> 4 {
	case 4:
		header := int(b[0]&15) * 4
		return len(b) >= 20 && header >= 20 && header <= len(b) && int(binary.BigEndian.Uint16(b[2:4])) == len(b)
	case 6:
		return len(b) >= 40 && int(binary.BigEndian.Uint16(b[4:6])) == len(b)-40
	default:
		return false
	}
}
func packetPump(src, dst *net.UnixConn, d packetrouter.Direction, p *packetrouter.RawPacketPolicy) error {
	// One buffer per direction. No idle work and no payload retained after write.
	b := make([]byte, 65575)
	for {
		n, _, flags, _, err := src.ReadMsgUnix(b, nil)
		if err != nil {
			return err
		}
		if flags&unix.MSG_TRUNC != 0 || !completeIP(b[:n]) {
			p.RejectInput(d, n)
			continue
		}
		if p.Apply(d, b[:n]) {
			if _, err = dst.Write(b[:n]); err != nil {
				return err
			}
		}
	}
}
func waitListener(ctx context.Context, a *attachment, parent int, v launch) error {
	name := C.CString(v.Proxy)
	defer C.free(unsafe.Pointer(name))
	timer := time.NewTicker(25 * time.Millisecond)
	defer timer.Stop()
	limit := time.NewTimer(5 * time.Second)
	defer limit.Stop()
	for {
		if C.owns_listener(C.int(a.pid), C.int(parent), name, C.int(v.Port)) == 1 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		case <-limit.C:
			return errors.New("ocproxy did not bind the requested loopback SOCKS port")
		}
	}
}
func Run(args []string) error {
	if len(args) == 3 && args[0] == "--ocproxy-attach" {
		return Attach(args[1], args[2])
	}
	if len(args) < 3 || args[0] != "--ocproxy-supervise" || args[len(args)-2] != "--" {
		return errors.New("invalid managed OpenConnect invocation")
	}
	v, err := readSettings(os.Stdin)
	if err != nil {
		return err
	}
	auth := make([]byte, v.AuthLength)
	if _, err = io.ReadFull(os.Stdin, auth); err != nil {
		return errors.New("incomplete OpenConnect sign-in input")
	}
	defer clear(auth)
	p, err := packetrouter.NewRawPacketPolicy(adapter, v.Profile, v.Kind, v.Source)
	if err != nil {
		return err
	}
	defer p.Close()
	me, err := os.Executable()
	if err != nil {
		return err
	}
	script := "exec " + quote(me) + " --ocproxy-attach " + quote(v.Proxy) + " " + strconv.Itoa(v.Port)
	clientArgs := append([]string{}, args[1:len(args)-2]...)
	clientArgs = append(clientArgs, "--script-tun", "--script", script, "--", args[len(args)-1])
	fds, err := socketPair()
	if err != nil {
		return err
	}
	ctl, err := channel(ownFile(fds[0], "script monitor"))
	child := ownFile(fds[1], "script handoff")
	if err != nil {
		child.Close()
		return err
	}
	cmd := exec.Command(v.Client, clientArgs...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	authRead, authWrite, err := os.Pipe()
	if err != nil {
		ctl.Close()
		child.Close()
		return err
	}
	cmd.Stdin = authRead
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.ExtraFiles = []*os.File{child}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer cancel()
	if err = cmd.Start(); err != nil {
		authRead.Close()
		authWrite.Close()
		child.Close()
		ctl.Close()
		return err
	}
	child.Close()
	authRead.Close()
	var workers sync.WaitGroup
	workers.Add(1)
	go func() { defer workers.Done(); defer authWrite.Close(); _, _ = authWrite.Write(auth); clear(auth) }()
	stats := make(chan struct{}, 1)
	go func() {
		var b [1]byte
		for {
			if _, e := io.ReadFull(os.Stdin, b[:]); e != nil || b[0] != 'S' {
				cancel()
				return
			}
			select {
			case stats <- struct{}{}:
			default:
			}
		}
	}()
	done := make(chan struct{})
	var childErr error
	go func() {
		if status := C.child_exit(C.int(cmd.Process.Pid)); status != 0 {
			childErr = fmt.Errorf("OpenConnect exited (%d)", int(status))
		}
		close(done)
	}()
	var a *attachment
	stopped := make(chan error, 5)
	defer func() {
		cancel()
		ctl.Close()
		_ = unix.Kill(-cmd.Process.Pid, unix.SIGTERM)
		if a != nil {
			a.close()
		}
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
		// No member of this group may outlive its verified SOCKS endpoint.
		_ = unix.Kill(-cmd.Process.Pid, unix.SIGKILL)
		<-done
		_ = cmd.Wait()
		workers.Wait()
	}()
	arrive := make(chan *attachment)
	workers.Add(1)
	go func() {
		defer workers.Done()
		next, e := receive(ctl)
		if e != nil {
			stopped <- e
			return
		}
		select {
		case arrive <- next:
		case <-ctx.Done():
			next.close()
		}
	}()
	select {
	case <-ctx.Done():
		return nil
	case <-done:
		if childErr != nil {
			return childErr
		}
		return errors.New("OpenConnect exited before attaching its packet path")
	case err = <-stopped:
		return err
	case a = <-arrive:
	}
	for i, pair := range [][2]*net.UnixConn{{a.local, a.vpn}, {a.vpn, a.local}} {
		workers.Add(1)
		go func() { defer workers.Done(); stopped <- packetPump(pair[0], pair[1], packetrouter.Direction(i), p) }()
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		var marker [1]byte
		a.life.Read(marker[:])
		stopped <- errors.New("ocproxy stopped")
	}()
	ready := make(chan error, 1)
	workers.Add(1)
	go func() { defer workers.Done(); ready <- waitListener(ctx, a, cmd.Process.Pid, v) }()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-done:
			return childErr
		case err = <-stopped:
			return err
		case err = <-ready:
			if err != nil {
				return err
			}
			fmt.Fprintln(os.Stdout, "SimpleVPN proxy ready "+v.Nonce)
		case <-stats:
			b, _ := json.Marshal(p.Status())
			fmt.Fprintln(os.Stdout, "SimpleVPN proxy stats "+v.Nonce+" "+string(b))
		}
	}
}
