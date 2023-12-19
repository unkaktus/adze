package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"
	"github.com/pkg/sftp"
	gossh "golang.org/x/crypto/ssh"
)

func setWinsize(f *os.File, w, h int) {
	syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCSWINSZ),
		uintptr(unsafe.Pointer(&struct{ h, w, x, y uint16 }{uint16(h), uint16(w), 0, 0})))
}

func SftpHandler(sess ssh.Session) {
	debugStream := io.Discard
	serverOptions := []sftp.ServerOption{
		sftp.WithDebug(debugStream),
	}
	server, err := sftp.NewServer(
		sess,
		serverOptions...,
	)
	if err != nil {
		log.Printf("sftp server init error: %s\n", err)
		return
	}
	if err := server.Serve(); err == io.EOF {
		server.Close()
		fmt.Println("sftp client exited session.")
	} else if err != nil {
		fmt.Println("sftp server completed with error:", err)
	}
}

func PtyHandler(s ssh.Session) {
	cmd := exec.Command(os.Getenv("SHELL"), "-l")
	cmd.Env = append(cmd.Env, os.Environ()...)
	ptyReq, winCh, isPty := s.Pty()
	if isPty {
		cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))
		f, err := pty.Start(cmd)
		if err != nil {
			panic(err)
		}
		go func() {
			for win := range winCh {
				setWinsize(f, win.Width, win.Height)
			}
		}()
		go func() {
			io.Copy(f, s) // stdin
		}()
		io.Copy(s, f) // stdout
		cmd.Wait()
	} else {
		io.WriteString(s, "No PTY requested.\n")
		s.Exit(1)
	}
}
func PublicKeyHandler(ctx ssh.Context, key ssh.PublicKey) bool {
	data, err := os.ReadFile(filepath.Join(os.Getenv("HOME"), ".ssh/authorized_keys"))
	if err != nil {
		log.Printf("read authorized_keys file: %v", err)
		return false
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		allowed, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(line))
		if ssh.KeysEqual(key, allowed) {
			return true
		}
	}
	return false
}

func run() error {
	portFlag := flag.Int("p", 2222, "listening port")
	flag.Parse()
	sshServer := ssh.Server{
		Addr:             "127.0.0.1:" + strconv.Itoa(*portFlag),
		Handler:          PtyHandler,
		PublicKeyHandler: PublicKeyHandler,
		SubsystemHandlers: map[string]ssh.SubsystemHandler{
			"sftp": SftpHandler,
		},
	}

	_, hostKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate host key: %w", err)
	}
	signer, err := gossh.NewSignerFromKey(hostKey)
	if err != nil {
		return fmt.Errorf("create signer: %w", err)
	}

	sshServer.AddHostKey(ssh.Signer(signer))

	hostPublickKey := gossh.MarshalAuthorizedKey(signer.PublicKey())

	fmt.Printf("hostKey:%s\n", hostPublickKey)

	log.Printf("listening on port %d", *portFlag)
	err = sshServer.ListenAndServe()

	if err != nil {
		return fmt.Errorf("listen and serve: %w", err)
	}

	return nil
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("%v", err)
	}
}
