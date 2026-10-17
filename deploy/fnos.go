package deploy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type FNOS struct {
	ssh     SSH
	domains map[string]bool
}

func init() {
	register("fnos", func(config Config) (Target, error) {
		values := config.Values
		port, err := strconv.Atoi(values["port"])
		if err != nil || port < 1 || port > 65535 {
			return nil, errors.New("FNOS SSH port is invalid")
		}
		connection := SSH{host: strings.TrimSpace(values["host"]), port: port, username: strings.TrimSpace(values["username"]), password: values["password"],
			hostKey: values["host_public_key"], knownHosts: values["known_hosts_file"], unsafeHost: values["insecure_skip_host_key"] == "true"}
		if connection.host == "" || connection.username == "" || connection.password == "" {
			return nil, errors.New("FNOS SSH connection details are required")
		}
		if !connection.unsafeHost && connection.hostKey == "" && connection.knownHosts == "" {
			return nil, errors.New("FNOS SSH host key verification is required")
		}
		domains := map[string]bool{}
		for _, domain := range splitList(values["domainList"]) {
			domains[strings.ToLower(domain)] = true
		}
		if len(domains) == 0 {
			return nil, errors.New("FNOS deployment domains are required")
		}
		return &FNOS{ssh: connection, domains: domains}, nil
	})
}

func (t *FNOS) Kind() string { return "fnos" }

func (t *FNOS) Check(ctx context.Context) error {
	connection, err := t.ssh.connect(ctx)
	if err != nil {
		return err
	}
	return connection.Close()
}

func (t *FNOS) Deploy(ctx context.Context, material Material) (Result, error) {
	leaf, err := certificate(material)
	if err != nil {
		return Result{}, err
	}
	connection, err := t.ssh.connect(ctx)
	if err != nil {
		return Result{}, err
	}
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	content, err := sshOutput(ctx, connection, "cat /usr/trim/etc/network_cert_all.conf")
	if err != nil {
		return Result{}, err
	}
	var listing []struct {
		SAN         []string `json:"san"`
		Certificate string   `json:"certificate"`
		PrivateKey  string   `json:"privateKey"`
		Domain      string   `json:"domain"`
	}
	if err := json.Unmarshal([]byte(content), &listing); err != nil {
		return Result{}, errors.New("invalid FNOS certificate list")
	}
	files, err := sftp.NewClient(connection)
	if err != nil {
		return Result{}, errors.New("start FNOS SFTP failed")
	}
	defer files.Close()
	result := Result{Target: t.Kind()}
	for _, item := range listing {
		matched := false
		for _, domain := range item.SAN {
			if t.domains[strings.ToLower(domain)] {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		if item.Certificate == "" || item.PrivateKey == "" {
			return result, errors.New("FNOS certificate paths are missing")
		}
		attempted, err := t.writePair(ctx, connection, files, item.Certificate, item.PrivateKey, material)
		if attempted {
			result.Written = true // either remote file may already have changed
		}
		if err != nil {
			return result, err
		}
		result.Written = true
		if result.Location != "" {
			result.Location += ","
		}
		result.Location += item.Domain
		query := fmt.Sprintf("UPDATE cert SET valid_to=%d,valid_from=%d,issued_by='%s',updated_time=%d WHERE private_key='%s';",
			leaf.NotAfter.UnixMilli(), leaf.NotBefore.UnixMilli(), sqlQuote(leaf.Issuer.CommonName), time.Now().UnixMilli(), sqlQuote(item.PrivateKey))
		if err := sshRun(ctx, connection, "sudo -u postgres psql -d trim_connect -c "+shQuote(query)); err != nil {
			return result, err
		}
	}
	if !result.Written {
		return result, errors.New("FNOS matching certificates were not found")
	}
	for _, service := range []string{"webdav.service", "smbftpd.service", "trim_nginx.service"} {
		if err := sshRun(ctx, connection, "sudo systemctl restart "+service); err != nil {
			return result, err
		}
	}
	return result, nil
}

func (t *FNOS) writePair(ctx context.Context, connection *ssh.Client, files *sftp.Client, certPath, keyPath string, material Material) (bool, error) {
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		return false, errors.New("FNOS temporary path generation failed")
	}
	base := "/tmp/dnsgo-" + hex.EncodeToString(random[:])
	certTemp, keyTemp := base+".crt", base+".key"
	if err := sftpWrite(files, certTemp, material.FullChainPEM, 0600, false); err != nil {
		return false, err
	}
	defer sshRun(ctx, connection, "rm -f "+shQuote(certTemp))
	if err := sftpWrite(files, keyTemp, material.PrivateKeyPEM, 0600, false); err != nil {
		return false, err
	}
	defer sshRun(ctx, connection, "rm -f "+shQuote(keyTemp))
	if err := sshRun(ctx, connection, "sudo cp "+shQuote(certTemp)+" "+shQuote(certPath)+" && sudo chmod 0644 "+shQuote(certPath)); err != nil {
		return true, err
	}
	if err := sshRun(ctx, connection, "sudo cp "+shQuote(keyTemp)+" "+shQuote(keyPath)+" && sudo chmod 0600 "+shQuote(keyPath)); err != nil {
		return true, err
	}
	return true, nil
}

func shQuote(value string) string  { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }
func sqlQuote(value string) string { return strings.ReplaceAll(value, "'", "''") }

var _ Target = (*FNOS)(nil)
