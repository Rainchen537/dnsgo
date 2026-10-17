package agent

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/rainchen537/dnsgo/automation"
	"go.yaml.in/yaml/v3"
)

type ProviderConfig struct {
	Kind        string            `yaml:"kind"`
	Domain      string            `yaml:"domain"`
	DomainID    string            `yaml:"domain_id"`
	Endpoint    string            `yaml:"endpoint"`
	ProxyURL    string            `yaml:"proxy_url"`
	Credentials map[string]string `yaml:"credentials"`
}

type ProbeConfig struct {
	Kind               automation.ProbeKind `yaml:"kind"`
	Target             string               `yaml:"target"`
	IP                 string               `yaml:"ip"`
	Port               int                  `yaml:"port"`
	Timeout            time.Duration        `yaml:"-"`
	TimeoutSeconds     int                  `yaml:"timeout_seconds"`
	InsecureSkipVerify bool                 `yaml:"insecure_skip_verify"`
	ProxyURL           string               `yaml:"proxy_url"`
}

func (c ProbeConfig) automation() automation.ProbeConfig {
	timeout := time.Duration(c.TimeoutSeconds) * time.Second
	return automation.ProbeConfig{Kind: c.Kind, Target: c.Target, IP: c.IP, Port: c.Port,
		Timeout: timeout, InsecureSkipVerify: c.InsecureSkipVerify, ProxyURL: c.ProxyURL}
}

type FailoverConfig struct {
	ID            string                  `yaml:"id"`
	Provider      string                  `yaml:"provider"`
	Mode          automation.FailoverMode `yaml:"mode"`
	ZoneID        string                  `yaml:"zone_id"`
	RecordID      string                  `yaml:"record_id"`
	Name          string                  `yaml:"name"`
	PrimaryValue  string                  `yaml:"primary_value"`
	BackupValue   string                  `yaml:"backup_value"`
	Cycle         int                     `yaml:"cycle"`
	ProxyOnBackup bool                    `yaml:"proxy_on_backup"`
	Probe         ProbeConfig             `yaml:"probe"`
	Siblings      []string                `yaml:"siblings"`
}

func (c FailoverConfig) automation() automation.FailoverTask {
	return automation.FailoverTask{Mode: c.Mode, ZoneID: c.ZoneID, RecordID: c.RecordID,
		Name: c.Name, PrimaryValue: c.PrimaryValue, BackupValue: c.BackupValue,
		Cycle: c.Cycle, ProxyOnBackup: c.ProxyOnBackup}
}

type ScheduleConfig struct {
	ID       string                    `yaml:"id"`
	Provider string                    `yaml:"provider"`
	Action   automation.ScheduleAction `yaml:"action"`
	Cycle    automation.ScheduleCycle  `yaml:"cycle"`
	ZoneID   string                    `yaml:"zone_id"`
	RecordID string                    `yaml:"record_id"`
	Name     string                    `yaml:"name"`
	Value    string                    `yaml:"value"`
	Line     string                    `yaml:"line"`
	TTL      int                       `yaml:"ttl"`
	At       string                    `yaml:"at"`
	Hour     int                       `yaml:"hour"`
	Minute   int                       `yaml:"minute"`
	Weekday  time.Weekday              `yaml:"weekday"`
	MonthDay int                       `yaml:"month_day"`
	Timezone string                    `yaml:"timezone"`
}

func (c ScheduleConfig) automation() (automation.ScheduleTask, error) {
	var at time.Time
	var err error
	if c.At != "" {
		at, err = time.Parse(time.RFC3339, c.At)
		if err != nil {
			return automation.ScheduleTask{}, fmt.Errorf("schedule %s at must be RFC3339: %w", c.ID, err)
		}
	}
	var location *time.Location
	if c.Timezone != "" {
		location, err = time.LoadLocation(c.Timezone)
		if err != nil {
			return automation.ScheduleTask{}, err
		}
	}
	return automation.ScheduleTask{Action: c.Action, Cycle: c.Cycle, ZoneID: c.ZoneID,
		RecordID: c.RecordID, Name: c.Name, Value: c.Value, Line: c.Line, TTL: c.TTL,
		At: at, Hour: c.Hour, Minute: c.Minute, Weekday: c.Weekday, MonthDay: c.MonthDay,
		Location: location}, nil
}

type ZoneConfig struct {
	Name     string `yaml:"name"`
	ID       string `yaml:"id"`
	Provider string `yaml:"provider"`
}

type DeploymentConfig struct {
	ID       string            `yaml:"id"`
	Target   string            `yaml:"target"`
	Endpoint string            `yaml:"endpoint"`
	ProxyURL string            `yaml:"proxy_url"`
	Values   map[string]string `yaml:"values"`
}

type CertificateConfig struct {
	ID               string             `yaml:"id"`
	Authority        string             `yaml:"authority"`
	CertFile         string             `yaml:"cert_file"`
	KeyFile          string             `yaml:"key_file"`
	Directory        string             `yaml:"directory"`
	Mode             string             `yaml:"mode"`
	ProxyURL         string             `yaml:"proxy_url"`
	Email            string             `yaml:"email"`
	AcceptTerms      bool               `yaml:"accept_terms"`
	EABMode          string             `yaml:"eab_mode"`
	EABKeyID         string             `yaml:"eab_key_id"`
	EABMACKey        string             `yaml:"eab_mac_key"`
	Domains          []string           `yaml:"domains"`
	KeyAlgorithm     string             `yaml:"key_algorithm"`
	KeySize          int                `yaml:"key_size"`
	RenewDays        int                `yaml:"renew_days"`
	Zones            []ZoneConfig       `yaml:"zones"`
	ChallengeAliases map[string]string  `yaml:"challenge_aliases"`
	Credentials      map[string]string  `yaml:"credentials"`
	Deployments      []DeploymentConfig `yaml:"deployments"`
	PropagationMins  int                `yaml:"propagation_minutes"`
}

type ExpiryConfig struct {
	Domains []string `yaml:"domains"`
	Days    []int    `yaml:"days"`
}

type NotificationConfig struct {
	ID       string            `yaml:"id"`
	Type     string            `yaml:"type"`
	ProxyURL string            `yaml:"proxy_url"`
	Values   map[string]string `yaml:"values"`
	Failover string            `yaml:"failover"`
	Cert     string            `yaml:"cert"`
	Expiry   string            `yaml:"expiry"`
}

type Config struct {
	Database      string                    `yaml:"database"`
	Interval      int                       `yaml:"interval_seconds"`
	Providers     map[string]ProviderConfig `yaml:"providers"`
	Failovers     []FailoverConfig          `yaml:"failovers"`
	Schedules     []ScheduleConfig          `yaml:"schedules"`
	Certificates  []CertificateConfig       `yaml:"certificates"`
	Expiry        ExpiryConfig              `yaml:"expiry"`
	Notifications []NotificationConfig      `yaml:"notifications"`
}

var envPattern = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

func expandEnv(value string) (string, error) {
	var missing string
	result := envPattern.ReplaceAllStringFunc(value, func(match string) string {
		name := match[2 : len(match)-1]
		v, ok := os.LookupEnv(name)
		if !ok || v == "" {
			missing = name
		}
		return v
	})
	if missing != "" {
		return "", fmt.Errorf("environment variable %s is missing", missing)
	}
	return result, nil
}

func expandMap(values map[string]string) (map[string]string, error) {
	result := make(map[string]string, len(values))
	for key, value := range values {
		resolved, err := expandEnv(value)
		if err != nil {
			return nil, fmt.Errorf("value %s: %w", key, err)
		}
		result[key] = resolved
	}
	return result, nil
}

func expandFields(fields ...*string) error {
	for _, field := range fields {
		value, err := expandEnv(*field)
		if err != nil {
			return err
		}
		*field = value
	}
	return nil
}

func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var config Config
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&config); err != nil {
		return Config{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err != nil {
			return Config{}, err
		}
		return Config{}, fmt.Errorf("configuration must contain exactly one YAML document")
	}
	if config.Database == "" {
		return Config{}, fmt.Errorf("database path is required")
	}
	config.Database, err = expandEnv(config.Database)
	if err != nil {
		return Config{}, err
	}
	if config.Interval <= 0 {
		config.Interval = 60
	}
	for name, provider := range config.Providers {
		if strings.TrimSpace(name) == "" || provider.Kind == "" {
			return Config{}, fmt.Errorf("provider profile name and kind are required")
		}
		provider.Credentials, err = expandMap(provider.Credentials)
		if err != nil {
			return Config{}, fmt.Errorf("provider %s: %w", name, err)
		}
		if err := expandFields(&provider.Kind, &provider.Domain, &provider.DomainID, &provider.Endpoint, &provider.ProxyURL); err != nil {
			return Config{}, fmt.Errorf("provider %s: %w", name, err)
		}
		config.Providers[name] = provider
	}
	for i := range config.Failovers {
		task := &config.Failovers[i]
		if err := expandFields(&task.ID, &task.Provider, &task.ZoneID, &task.RecordID, &task.Name,
			&task.PrimaryValue, &task.BackupValue, &task.Probe.Target, &task.Probe.IP, &task.Probe.ProxyURL); err != nil {
			return Config{}, err
		}
		for j := range task.Siblings {
			if err := expandFields(&task.Siblings[j]); err != nil {
				return Config{}, err
			}
		}
	}
	for i := range config.Schedules {
		task := &config.Schedules[i]
		if err := expandFields(&task.ID, &task.Provider, &task.ZoneID, &task.RecordID, &task.Name,
			&task.Value, &task.Line, &task.At, &task.Timezone); err != nil {
			return Config{}, err
		}
	}
	for i := range config.Certificates {
		cert := &config.Certificates[i]
		if err := expandFields(&cert.ID, &cert.Authority, &cert.CertFile, &cert.KeyFile,
			&cert.Directory, &cert.Mode, &cert.ProxyURL, &cert.Email, &cert.EABMode, &cert.EABKeyID, &cert.EABMACKey); err != nil {
			return Config{}, err
		}
		cert.Credentials, err = expandMap(cert.Credentials)
		if err != nil {
			return Config{}, fmt.Errorf("certificate %s: %w", cert.ID, err)
		}
		for j := range cert.Domains {
			if err := expandFields(&cert.Domains[j]); err != nil {
				return Config{}, err
			}
		}
		for j := range cert.Zones {
			zone := &cert.Zones[j]
			if err := expandFields(&zone.Name, &zone.ID, &zone.Provider); err != nil {
				return Config{}, err
			}
		}
		cert.ChallengeAliases, err = expandMap(cert.ChallengeAliases)
		if err != nil {
			return Config{}, err
		}
		for j := range cert.Deployments {
			deployment := &cert.Deployments[j]
			if err := expandFields(&deployment.ID, &deployment.Target, &deployment.Endpoint, &deployment.ProxyURL); err != nil {
				return Config{}, err
			}
			deployment.Values, err = expandMap(deployment.Values)
			if err != nil {
				return Config{}, fmt.Errorf("certificate %s deployment %s: %w", cert.ID, deployment.ID, err)
			}
		}
	}
	for i := range config.Expiry.Domains {
		if err := expandFields(&config.Expiry.Domains[i]); err != nil {
			return Config{}, err
		}
	}
	for i := range config.Notifications {
		n := &config.Notifications[i]
		if err := expandFields(&n.ID, &n.Type, &n.ProxyURL, &n.Failover, &n.Cert, &n.Expiry); err != nil {
			return Config{}, err
		}
		n.Values, err = expandMap(n.Values)
		if err != nil {
			return Config{}, fmt.Errorf("notification %s: %w", n.ID, err)
		}
	}
	return config, nil
}
