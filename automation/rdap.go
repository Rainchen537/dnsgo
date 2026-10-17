package automation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// RDAPLookup discovers authoritative domain RDAP services via the IANA DNS
// bootstrap registry. Bootstrap results are cached for one day.
type RDAPLookup struct {
	Client       *http.Client
	BootstrapURL string
	mu           sync.Mutex
	services     []rdapService
	loaded       time.Time
}

type rdapService struct {
	TLDs []string
	URLs []string
}

func (r *RDAPLookup) httpClient() *http.Client {
	if r.Client != nil {
		return r.Client
	}
	return &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

func domainForLookup(name string) (string, error) {
	name = strings.Trim(strings.ToLower(strings.TrimSpace(name)), ".")
	ascii, err := idna.Lookup.ToASCII(name)
	if err != nil || ascii == "" || len(ascii) > 253 {
		return "", fmt.Errorf("invalid domain name")
	}
	for _, label := range strings.Split(ascii, ".") {
		if label == "" || len(label) > 63 {
			return "", fmt.Errorf("invalid domain name")
		}
	}
	registered, err := publicsuffix.EffectiveTLDPlusOne(ascii)
	if err != nil {
		return "", fmt.Errorf("cannot determine registrable domain: %w", err)
	}
	return registered, nil
}

// RegisteredDomain returns the eTLD+1 name used for RDAP/WHOIS expiry lookup.
func RegisteredDomain(name string) (string, error) { return domainForLookup(name) }

func (r *RDAPLookup) load(ctx context.Context) ([]rdapService, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.services) > 0 && time.Since(r.loaded) < 24*time.Hour {
		return append([]rdapService(nil), r.services...), nil
	}
	endpoint := r.BootstrapURL
	if endpoint == "" {
		endpoint = "https://data.iana.org/rdap/dns.json"
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return nil, fmt.Errorf("RDAP bootstrap URL must be HTTPS")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	response, err := r.httpClient().Do(request)
	if err != nil {
		return nil, fmt.Errorf("RDAP bootstrap request failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("RDAP bootstrap returned HTTP %d", response.StatusCode)
	}
	var bootstrap struct {
		Services [][][]string `json:"services"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 4<<20)).Decode(&bootstrap); err != nil {
		return nil, fmt.Errorf("invalid RDAP bootstrap JSON: %w", err)
	}
	services := make([]rdapService, 0, len(bootstrap.Services))
	for _, pair := range bootstrap.Services {
		if len(pair) == 2 {
			services = append(services, rdapService{TLDs: pair[0], URLs: pair[1]})
		}
	}
	if len(services) == 0 {
		return nil, fmt.Errorf("RDAP bootstrap has no services")
	}
	r.services, r.loaded = services, time.Now()
	return append([]rdapService(nil), services...), nil
}

func (r *RDAPLookup) LookupDomain(ctx context.Context, name string) (time.Time, time.Time, error) {
	domain, err := domainForLookup(name)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	services, err := r.load(ctx)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	var bases []string
	longest := 0
	for _, service := range services {
		for _, tld := range service.TLDs {
			tld = strings.Trim(strings.ToLower(tld), ".")
			if domain == tld || strings.HasSuffix(domain, "."+tld) {
				if len(tld) > longest {
					longest, bases = len(tld), nil
				}
				if len(tld) == longest {
					bases = append(bases, service.URLs...)
				}
			}
		}
	}
	if len(bases) == 0 {
		return time.Time{}, time.Time{}, fmt.Errorf("no RDAP service registered for %s", domain)
	}
	sort.Strings(bases)
	var lastErr error
	for _, base := range bases {
		parsed, err := url.Parse(base)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
			lastErr = fmt.Errorf("RDAP service URL must be HTTPS")
			continue
		}
		endpoint := strings.TrimRight(base, "/") + "/domain/" + url.PathEscape(domain)
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			lastErr = err
			continue
		}
		request.Header.Set("Accept", "application/rdap+json")
		response, err := r.httpClient().Do(request)
		if err != nil {
			lastErr = err
			continue
		}
		if response.StatusCode != 200 {
			_ = response.Body.Close()
			lastErr = fmt.Errorf("RDAP service returned HTTP %d", response.StatusCode)
			continue
		}
		var result struct {
			ObjectClassName string `json:"objectClassName"`
			Events          []struct {
				Action string `json:"eventAction"`
				Date   string `json:"eventDate"`
			} `json:"events"`
		}
		decodeErr := json.NewDecoder(io.LimitReader(response.Body, 4<<20)).Decode(&result)
		_ = response.Body.Close()
		if decodeErr != nil || result.ObjectClassName != "domain" {
			lastErr = fmt.Errorf("invalid RDAP domain response")
			continue
		}
		var registered, expires time.Time
		for _, event := range result.Events {
			date, err := time.Parse(time.RFC3339, event.Date)
			if err != nil {
				continue
			}
			switch event.Action {
			case "registration":
				registered = date
			case "expiration":
				expires = date
			}
		}
		if expires.IsZero() {
			lastErr = fmt.Errorf("RDAP response contains no expiration event")
			continue
		}
		return registered, expires, nil
	}
	return time.Time{}, time.Time{}, lastErr
}
