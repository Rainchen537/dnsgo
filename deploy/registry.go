package deploy

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

type Config struct {
	Values     map[string]string
	Domains    []string // certificate DNS names; fills domainList when not explicitly configured
	Endpoint   string
	HTTPClient *http.Client
}

type Factory func(Config) (Target, error)

var factories = map[string]Factory{}

func register(name string, factory Factory) {
	if _, exists := factories[name]; exists {
		panic("duplicate certificate deployment target: " + name)
	}
	factories[name] = factory
}

// Names lists implemented Go targets. Compare with the upstream inventory for
// the 50-target release gate; an adapter name alone does not prove behavior.
func Names() []string {
	names := make([]string, 0, len(factories))
	for name := range factories {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func New(name string, config Config) (Target, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	factory, ok := factories[name]
	if !ok {
		return nil, fmt.Errorf("unknown certificate deployment target %q", name)
	}
	if len(config.Domains) > 0 && config.Values["domainList"] == "" {
		values := make(map[string]string, len(config.Values)+1)
		for key, value := range config.Values {
			values[key] = value
		}
		values["domainList"] = strings.Join(config.Domains, ",")
		config.Values = values
	}
	return factory(config)
}

func client(config Config) *http.Client {
	if config.HTTPClient != nil {
		return config.HTTPClient
	}
	return &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}
