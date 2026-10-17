package deploy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	ftpclient "github.com/jlaffaye/ftp"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

type FTP struct {
	host        string
	port        int
	username    string
	password    string
	secure      bool
	insecureTLS bool
	format      string
	certPath    string
	keyPath     string
	pfxPath     string
	pfxPass     string
}

func init() {
	register("ftp", func(config Config) (Target, error) {
		values := config.Values
		port, err := strconv.Atoi(values["port"])
		if err != nil || port < 1 || port > 65535 {
			return nil, errors.New("FTP port must be 1 through 65535")
		}
		target := &FTP{host: strings.TrimSpace(values["host"]), port: port, username: strings.TrimSpace(values["username"]), password: values["password"],
			secure: values["secure"] == "1", insecureTLS: values["insecure_skip_verify"] == "true", format: values["format"],
			certPath: values["pem_cert_file"], keyPath: values["pem_key_file"], pfxPath: values["pfx_file"], pfxPass: values["pfx_pass"]}
		if target.host == "" || target.username == "" || target.password == "" {
			return nil, errors.New("FTP host, username and password are required")
		}
		if target.format == "pem" && (target.certPath == "" || target.keyPath == "" || target.certPath == target.keyPath) {
			return nil, errors.New("FTP PEM paths must be distinct and nonempty")
		}
		if target.format == "pfx" && target.pfxPath == "" {
			return nil, errors.New("FTP PFX path is required")
		}
		if target.format != "pem" && target.format != "pfx" {
			return nil, errors.New("FTP format must be pem or pfx")
		}
		for _, path := range []string{target.certPath, target.keyPath, target.pfxPath} {
			if strings.ContainsAny(path, "\r\n\x00") {
				return nil, errors.New("FTP path contains invalid characters")
			}
		}
		return target, nil
	})
}

func (t *FTP) Kind() string { return "ftp" }

func (t *FTP) Check(ctx context.Context) error {
	connection, err := t.connect(ctx)
	if err != nil {
		return err
	}
	return connection.Quit()
}

func (t *FTP) Deploy(ctx context.Context, material Material) (Result, error) {
	pair, err := tls.X509KeyPair(material.FullChainPEM, material.PrivateKeyPEM)
	if err != nil {
		return Result{}, errors.New("certificate and private key are invalid or do not match")
	}
	connection, err := t.connect(ctx)
	if err != nil {
		return Result{}, err
	}
	defer connection.Quit()
	result := Result{Target: t.Kind()}
	if t.format == "pem" {
		result.Location = t.certPath
		result.Written = true // STOR may partially replace the destination before failing.
		if err := connection.Stor(t.certPath, bytes.NewReader(material.FullChainPEM)); err != nil {
			return result, errors.New("FTP certificate upload failed")
		}
		if err := connection.Stor(t.keyPath, bytes.NewReader(material.PrivateKeyPEM)); err != nil {
			return result, errors.New("FTP private key upload failed after certificate upload")
		}
		return result, nil
	}
	encoded, err := ftpPFX(pair, t.pfxPass)
	if err != nil {
		return Result{}, err
	}
	result.Location = t.pfxPath
	result.Written = true
	if err := connection.Stor(t.pfxPath, bytes.NewReader(encoded)); err != nil {
		return result, errors.New("FTP PFX upload failed")
	}
	return result, nil
}

func ftpPFX(pair tls.Certificate, password string) ([]byte, error) {
	if len(pair.Certificate) == 0 {
		return nil, errors.New("certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, errors.New("invalid certificate leaf")
	}
	chain := make([]*x509.Certificate, 0, len(pair.Certificate)-1)
	for _, der := range pair.Certificate[1:] {
		issuer, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, errors.New("invalid certificate chain")
		}
		chain = append(chain, issuer)
	}
	encoded, err := pkcs12.Modern2023.Encode(pair.PrivateKey, leaf, chain, password)
	if err != nil {
		return nil, errors.New("encode PFX failed")
	}
	return encoded, nil
}

func (t *FTP) connect(ctx context.Context) (*ftpclient.ServerConn, error) {
	options := []ftpclient.DialOption{ftpclient.DialWithTimeout(10 * time.Second), ftpclient.DialWithContext(ctx)}
	if t.secure {
		options = append(options, ftpclient.DialWithExplicitTLS(&tls.Config{ServerName: t.host, MinVersion: tls.VersionTLS12, InsecureSkipVerify: t.insecureTLS}))
	}
	connection, err := ftpclient.Dial(net.JoinHostPort(t.host, strconv.Itoa(t.port)), options...)
	if err != nil {
		return nil, fmt.Errorf("FTP connection failed")
	}
	if err := connection.Login(t.username, t.password); err != nil {
		_ = connection.Quit()
		return nil, errors.New("FTP login failed")
	}
	return connection, nil
}

var _ Target = (*FTP)(nil)
