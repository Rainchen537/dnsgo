package deploy

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type SSH struct {
	host          string
	port          int
	username      string
	password      string
	privateKey    string
	useKey        bool
	passphrase    string
	hostKey       string
	knownHosts    string
	unsafeHost    bool
	windows       bool
	format        string
	certPath      string
	keyPath       string
	pfxPath       string
	pfxPass       string
	preCommands   []string
	commands      []string
	iisDomain     string
	allowCommands bool
}

func init() {
	register("ssh", func(config Config) (Target, error) {
		values := config.Values
		port, err := strconv.Atoi(values["port"])
		if err != nil || port < 1 || port > 65535 {
			return nil, errors.New("SSH port must be 1 through 65535")
		}
		target := &SSH{host: strings.TrimSpace(values["host"]), port: port, username: strings.TrimSpace(values["username"]),
			password: values["password"], privateKey: values["privatekey"], useKey: values["auth"] == "1", passphrase: values["passphrase"],
			hostKey: values["host_public_key"], knownHosts: values["known_hosts_file"], unsafeHost: values["insecure_skip_host_key"] == "true", windows: values["windows"] == "1",
			format: values["format"], certPath: values["pem_cert_file"], keyPath: values["pem_key_file"], pfxPath: values["pfx_file"],
			pfxPass: values["pfx_pass"], preCommands: splitCommands(values["cmd_pre"]), commands: splitCommands(values["cmd"]),
			iisDomain: strings.TrimSpace(values["iis_domain"]), allowCommands: values["allow_commands"] == "true"}
		if target.host == "" || target.username == "" {
			return nil, errors.New("SSH host and username are required")
		}
		if values["auth"] == "1" && target.privateKey == "" || values["auth"] != "1" && target.password == "" {
			return nil, errors.New("SSH authentication credentials are required")
		}
		if !target.unsafeHost && target.hostKey == "" && target.knownHosts == "" {
			return nil, errors.New("SSH host key, known_hosts file or explicit insecure opt-in is required")
		}
		if target.format != "pem" && target.format != "pfx" {
			return nil, errors.New("SSH format must be pem or pfx")
		}
		if target.format == "pem" && (target.certPath == "" || target.keyPath == "" || target.certPath == target.keyPath) {
			return nil, errors.New("SSH PEM paths must be distinct and nonempty")
		}
		if target.format == "pfx" && target.pfxPath == "" {
			return nil, errors.New("SSH PFX path is required")
		}
		if target.iisDomain != "" && target.format != "pfx" {
			return nil, errors.New("IIS deployment requires PFX format")
		}
		if (len(target.preCommands) > 0 || len(target.commands) > 0 || target.iisDomain != "") && !target.allowCommands {
			return nil, errors.New("SSH remote commands require allow_commands=true")
		}
		return target, nil
	})
}

func (t *SSH) Kind() string { return "ssh" }

func (t *SSH) Check(ctx context.Context) error {
	connection, err := t.connect(ctx)
	if err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	return connection.Close()
}

func (t *SSH) Deploy(ctx context.Context, material Material) (Result, error) {
	pair, err := tls.X509KeyPair(material.FullChainPEM, material.PrivateKeyPEM)
	if err != nil {
		return Result{}, errors.New("certificate and private key are invalid or do not match")
	}
	connection, err := t.connect(ctx)
	if err != nil {
		return Result{}, err
	}
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	result := Result{Target: t.Kind()}
	for _, command := range t.preCommands {
		result.Written = true // caller-supplied command may already have changed remote state
		if err := sshRun(ctx, connection, command); err != nil {
			return result, err
		}
	}
	files, err := sftp.NewClient(connection)
	if err != nil {
		return result, errors.New("start SSH SFTP failed")
	}
	defer files.Close()
	if t.format == "pem" {
		result.Location = t.certPath
		result.Written = true // SFTP writes can be partial on failure
		if err := sftpWrite(files, t.certPath, material.FullChainPEM, 0644, t.windows); err != nil {
			return result, err
		}
		result.Written = true
		if err := sftpWrite(files, t.keyPath, material.PrivateKeyPEM, 0600, t.windows); err != nil {
			return result, err
		}
	} else {
		encoded, err := ftpPFX(pair, t.pfxPass)
		if err != nil {
			return result, err
		}
		result.Location = t.pfxPath
		result.Written = true
		if err := sftpWrite(files, t.pfxPath, encoded, 0600, t.windows); err != nil {
			return result, err
		}
		result.Written = true
		if t.iisDomain != "" {
			if err := t.deployIIS(ctx, connection, pair, t.iisDomain); err != nil {
				return result, err
			}
			return result, nil
		}
	}
	for _, command := range t.commands {
		if err := sshRun(ctx, connection, command); err != nil {
			return result, err
		}
	}
	return result, nil
}

func splitCommands(source string) []string {
	var result []string
	for _, command := range strings.Split(source, "\n") {
		if command = strings.TrimSpace(command); command != "" {
			result = append(result, command)
		}
	}
	return result
}

func sftpWrite(client *sftp.Client, path string, data []byte, mode os.FileMode, skipChmod bool) error {
	if path == "" || strings.ContainsAny(path, "\x00\r\n") {
		return errors.New("invalid SFTP target path")
	}
	file, err := client.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return errors.New("open SFTP target failed")
	}
	written, writeErr := file.Write(data)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil || written != len(data) {
		return errors.New("write SFTP target failed")
	}
	if !skipChmod {
		if err := client.Chmod(path, mode); err != nil {
			return errors.New("set SFTP target permission failed")
		}
	}
	return nil
}

func sshRun(ctx context.Context, client *ssh.Client, command string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	session, err := client.NewSession()
	if err != nil {
		return errors.New("open SSH command session failed")
	}
	defer session.Close()
	// Do not surface command output: it can contain credentials or key material.
	if _, err := session.CombinedOutput(command); err != nil {
		return errors.New("SSH remote command failed")
	}
	return nil
}

func (t *SSH) connect(ctx context.Context) (*ssh.Client, error) {
	var auth ssh.AuthMethod
	if t.useKey {
		var signer ssh.Signer
		var err error
		if t.passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(t.privateKey), []byte(t.passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(t.privateKey))
		}
		if err != nil {
			return nil, errors.New("parse SSH private key failed")
		}
		auth = ssh.PublicKeys(signer)
	} else {
		auth = ssh.Password(t.password)
	}
	var hostCallback ssh.HostKeyCallback
	switch {
	case t.hostKey != "":
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(t.hostKey))
		if err != nil {
			return nil, errors.New("invalid SSH host public key")
		}
		hostCallback = ssh.FixedHostKey(key)
	case t.knownHosts != "":
		callback, err := knownhosts.New(t.knownHosts)
		if err != nil {
			return nil, errors.New("read SSH known_hosts failed")
		}
		hostCallback = callback
	case t.unsafeHost:
		hostCallback = ssh.InsecureIgnoreHostKey()
	default:
		return nil, errors.New("SSH host verification is required")
	}
	address := net.JoinHostPort(t.host, strconv.Itoa(t.port))
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	connection, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, errors.New("SSH TCP connection failed")
	}
	configuration := &ssh.ClientConfig{User: t.username, Auth: []ssh.AuthMethod{auth}, HostKeyCallback: hostCallback, Timeout: 10 * time.Second}
	_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
	secureConn, channels, requests, err := ssh.NewClientConn(connection, address, configuration)
	if err != nil {
		_ = connection.Close()
		return nil, errors.New("SSH handshake or authentication failed")
	}
	_ = connection.SetDeadline(time.Time{})
	return ssh.NewClient(secureConn, channels, requests), nil
}

var iisDomainPattern = regexp.MustCompile(`^[A-Za-z0-9*.-]+(?::[0-9]{1,5})?$`)
var iisHashPattern = regexp.MustCompile(`(?i)[0-9a-f]{40}`)

func (t *SSH) deployIIS(ctx context.Context, client *ssh.Client, pair tls.Certificate, domain string) error {
	if !iisDomainPattern.MatchString(domain) {
		return errors.New("invalid IIS binding domain")
	}
	if !strings.Contains(domain, ":") {
		domain += ":443"
	}
	if len(pair.Certificate) == 0 {
		return errors.New("IIS certificate leaf is missing")
	}
	digest := sha1.Sum(pair.Certificate[0])
	hash := strings.ToUpper(hex.EncodeToString(digest[:]))
	output, _ := sshOutput(ctx, client, "netsh http show sslcert hostnameport="+domain)
	if found := iisHashPattern.FindString(output); strings.EqualFold(found, hash) {
		return nil
	}
	pfxPath := strings.TrimPrefix(t.pfxPath, "/")
	if strings.ContainsAny(pfxPath, "\"\r\n&|<>^%!") || strings.ContainsAny(t.pfxPass, "\"\r\n&|<>^%!") {
		return errors.New("IIS PFX path or password contains unsupported shell characters")
	}
	if err := sshRun(ctx, client, `certutil -p "`+t.pfxPass+`" -importPFX "`+pfxPath+`"`); err != nil {
		return err
	}
	if found := iisHashPattern.FindString(output); found != "" {
		if err := sshRun(ctx, client, "netsh http delete sslcert hostnameport="+domain); err != nil {
			return err
		}
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return errors.New("IIS binding UUID generation failed")
	}
	random[6] = random[6]&0x0f | 0x40
	random[8] = random[8]&0x3f | 0x80
	uuid := fmt.Sprintf("%x-%x-%x-%x-%x", random[:4], random[4:6], random[6:8], random[8:10], random[10:])
	return sshRun(ctx, client, "netsh http add sslcert hostnameport="+domain+" certhash="+hash+" certstorename=MY appid={"+uuid+"}")
}

func sshOutput(ctx context.Context, client *ssh.Client, command string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	session, err := client.NewSession()
	if err != nil {
		return "", errors.New("open SSH command session failed")
	}
	defer session.Close()
	output, err := session.CombinedOutput(command)
	if err != nil {
		return "", errors.New("SSH remote command failed")
	}
	return string(output), nil
}

var _ Target = (*SSH)(nil)
