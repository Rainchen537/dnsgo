package deploy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

type LocalConfig struct {
	Format        string // pem or pfx
	PEMCertPath   string
	PEMKeyPath    string
	PFXPath       string
	PFXPassword   string
	Commands      []string // optional shell commands after a successful write
	AllowCommands bool
}

type Local struct{ Config LocalConfig }

func init() {
	register("local", func(config Config) (Target, error) {
		values := config.Values
		local := &Local{Config: LocalConfig{Format: values["format"], PEMCertPath: values["pem_cert_file"],
			PEMKeyPath: values["pem_key_file"], PFXPath: values["pfx_file"], PFXPassword: values["pfx_pass"],
			AllowCommands: values["allow_commands"] == "true"}}
		if commands := strings.TrimSpace(values["cmd"]); commands != "" {
			local.Config.Commands = strings.Split(commands, "\n")
		}
		if err := local.Check(context.Background()); err != nil {
			return nil, err
		}
		return local, nil
	})
}

func (l *Local) Kind() string { return "local" }

func (l *Local) Check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var paths []string
	switch strings.ToLower(l.Config.Format) {
	case "pem":
		paths = []string{l.Config.PEMCertPath, l.Config.PEMKeyPath}
		if paths[0] == paths[1] {
			return errors.New("PEM certificate and key paths must differ")
		}
	case "pfx":
		paths = []string{l.Config.PFXPath}
	default:
		return errors.New("local deployment format must be pem or pfx")
	}
	for _, path := range paths {
		if path == "" || !filepath.IsAbs(path) {
			return errors.New("certificate paths must be absolute")
		}
		dir := filepath.Dir(path)
		info, err := os.Stat(dir)
		if err != nil {
			return fmt.Errorf("certificate directory %s: %w", dir, err)
		}
		if !info.IsDir() {
			return fmt.Errorf("certificate path parent %s is not a directory", dir)
		}
	}
	if len(l.Config.Commands) > 0 && !l.Config.AllowCommands {
		return errors.New("local deployment commands require AllowCommands")
	}
	return nil
}

func (l *Local) Deploy(ctx context.Context, material Material) (Result, error) {
	if err := l.Check(ctx); err != nil {
		return Result{}, err
	}
	pair, err := tls.X509KeyPair(material.FullChainPEM, material.PrivateKeyPEM)
	if err != nil {
		return Result{}, fmt.Errorf("certificate and private key do not match: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return Result{}, errors.New("certificate chain is empty")
	}
	var location string
	switch strings.ToLower(l.Config.Format) {
	case "pem":
		written, err := writePEMPair(l.Config.PEMCertPath, l.Config.PEMKeyPath, material)
		if err != nil {
			return Result{Target: l.Kind(), Location: l.Config.PEMCertPath, Written: written}, err
		}
		location = l.Config.PEMCertPath
	case "pfx":
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return Result{}, err
		}
		chain := make([]*x509.Certificate, 0, len(pair.Certificate)-1)
		for _, der := range pair.Certificate[1:] {
			issuer, err := x509.ParseCertificate(der)
			if err != nil {
				return Result{}, err
			}
			chain = append(chain, issuer)
		}
		encoded, err := pkcs12.Modern2023.Encode(pair.PrivateKey, leaf, chain, l.Config.PFXPassword)
		if err != nil {
			return Result{}, fmt.Errorf("encode PFX: %w", err)
		}
		if err := writeAtomic(l.Config.PFXPath, encoded, 0600); err != nil {
			return Result{Target: l.Kind(), Location: l.Config.PFXPath, Written: true}, err
		}
		location = l.Config.PFXPath
	}
	result := Result{Target: l.Kind(), Location: location, Written: true}
	for _, command := range l.Config.Commands {
		command = strings.TrimSpace(command)
		if command == "" {
			continue
		}
		if err := ctx.Err(); err != nil {
			return result, err
		}
		cmd := exec.CommandContext(ctx, "/bin/sh", "-c", command)
		if _, err := cmd.CombinedOutput(); err != nil {
			// Shell output can include certificate or credential material.
			return result, fmt.Errorf("post-deployment command failed: %w", err)
		}
	}
	return result, nil
}

func stageFile(path string, data []byte, mode os.FileMode) (string, error) {
	file, err := os.CreateTemp(filepath.Dir(path), ".dnsgo-*")
	if err != nil {
		return "", err
	}
	name := file.Name()
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(name)
		}
	}()
	if err := file.Chmod(mode); err != nil {
		return "", err
	}
	if _, err := file.Write(data); err != nil {
		return "", err
	}
	if err := file.Sync(); err != nil {
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	remove = false
	return name, nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	staged, err := stageFile(path, data, mode)
	if err != nil {
		return err
	}
	defer os.Remove(staged)
	return os.Rename(staged, path)
}

func writePEMPair(certPath, keyPath string, material Material) (bool, error) {
	previous, err := os.ReadFile(certPath)
	previousExists := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("read existing certificate: %w", err)
	}
	certStage, err := stageFile(certPath, material.FullChainPEM, 0644)
	if err != nil {
		return false, err
	}
	defer os.Remove(certStage)
	keyStage, err := stageFile(keyPath, material.PrivateKeyPEM, 0600)
	if err != nil {
		return false, err
	}
	defer os.Remove(keyStage)
	if err := os.Rename(certStage, certPath); err != nil {
		return false, err
	}
	if err := os.Rename(keyStage, keyPath); err != nil {
		var rollback error
		if previousExists {
			rollback = writeAtomic(certPath, previous, 0644)
		} else {
			rollback = os.Remove(certPath)
		}
		return true, errors.Join(fmt.Errorf("write private key: %w", err), rollback)
	}
	return true, nil
}

var _ Target = (*Local)(nil)
