// Package providers constructs DnsGo's cloud DNS adapters.
package providers

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/rainchen537/dnsgo"
)

type Factory func(dnsgo.Config) (dnsgo.Provider, error)

var factories = map[string]Factory{}

func register(name string, factory Factory) {
	if _, exists := factories[name]; exists {
		panic("duplicate DNS provider: " + name)
	}
	factories[name] = factory
}

// Names lists implemented Go adapters, not the PHP reference inventory.
func Names() []string {
	names := make([]string, 0, len(factories))
	for name := range factories {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func New(name string, config dnsgo.Config) (dnsgo.Provider, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	factory, ok := factories[name]
	if !ok {
		return nil, &dnsgo.Error{Provider: name, Operation: "new", Code: dnsgo.CodeUnsupported, Message: fmt.Sprintf("unknown DNS provider %q", name)}
	}
	return factory(config)
}

func client(config dnsgo.Config) *http.Client {
	if config.HTTPClient != nil {
		return config.HTTPClient
	}
	return &http.Client{
		Timeout: 20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
