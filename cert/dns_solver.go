package cert

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/mholt/acmez/v3/acme"
	"github.com/rainchen537/dnsgo"
)

// ZoneBinding directs ACME TXT records to a DNS provider zone. A single
// certificate can use different providers for its SANs.
type ZoneBinding struct {
	Name     string
	ID       string
	Provider dnsgo.Provider
}

type challengeRecord struct {
	zone   ZoneBinding
	record dnsgo.Record
	name   string
	owned  bool
}

type dnsSolver struct {
	zones    []ZoneBinding
	aliases  map[string]string
	timeout  time.Duration
	poll     time.Duration
	observer ChallengeObserver
	mu       sync.Mutex
	created  map[string]challengeRecord
}

func newDNSSolver(zones []ZoneBinding, aliases map[string]string, timeout, poll time.Duration, observer ChallengeObserver) (*dnsSolver, error) {
	clean := make([]ZoneBinding, 0, len(zones))
	seen := map[string]bool{}
	for _, zone := range zones {
		zone.Name = canonicalDomain(zone.Name)
		if zone.Name == "" || zone.ID == "" || zone.Provider == nil {
			return nil, &dnsgo.Error{Provider: "acme", Operation: "dns_solver", Code: dnsgo.CodeInvalidInput, Message: "zone name, ID and provider are required"}
		}
		if seen[zone.Name] {
			return nil, &dnsgo.Error{Provider: "acme", Operation: "dns_solver", Code: dnsgo.CodeInvalidInput, Message: "duplicate zone binding"}
		}
		seen[zone.Name] = true
		clean = append(clean, zone)
	}
	cleanAliases := make(map[string]string, len(aliases))
	for source, target := range aliases {
		cleanAliases[canonicalDomain(source)] = canonicalDomain(target)
	}
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	if poll <= 0 {
		poll = 5 * time.Second
	}
	return &dnsSolver{zones: clean, aliases: cleanAliases, timeout: timeout, poll: poll, observer: observer,
		created: make(map[string]challengeRecord)}, nil
}

func canonicalDomain(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

func (s *dnsSolver) binding(name string) (ZoneBinding, string, error) {
	name = canonicalDomain(name)
	var best ZoneBinding
	for _, zone := range s.zones {
		if (name == zone.Name || strings.HasSuffix(name, "."+zone.Name)) && len(zone.Name) > len(best.Name) {
			best = zone
		}
	}
	if best.Name == "" {
		return ZoneBinding{}, "", &dnsgo.Error{Provider: "acme", Operation: "dns_solver", Code: dnsgo.CodeNotFound, Message: "no DNS zone binding for challenge"}
	}
	relative := "@"
	if name != best.Name {
		relative = strings.TrimSuffix(name, "."+best.Name)
	}
	return best, relative, nil
}

func (s *dnsSolver) challengeName(challenge acme.Challenge) string {
	name := canonicalDomain(challenge.DNS01TXTRecordName())
	if alias := s.aliases[name]; alias != "" {
		return alias
	}
	return name
}

func (s *dnsSolver) Present(ctx context.Context, challenge acme.Challenge) error {
	name := s.challengeName(challenge)
	zone, relative, err := s.binding(name)
	if err != nil {
		return err
	}
	value := challenge.DNS01KeyAuthorization()
	tracked := ChallengeRecord{ChallengeURL: challenge.URL, Provider: zone.Provider.Kind(), ZoneID: zone.ID,
		Name: name, Type: "TXT", Value: value}
	listed, err := dnsgo.ListSubdomainRecords(ctx, zone.Provider, dnsgo.Zone{ID: zone.ID, Name: zone.Name}, relative,
		dnsgo.SubdomainQuery{Type: "TXT", PageSize: int(^uint(0) >> 1)})
	if err != nil {
		return err
	}
	for _, existing := range listed.Items {
		if existing.Value != value {
			continue
		}
		if existing.ID == "" || existing.Enabled != nil && !*existing.Enabled {
			return &dnsgo.Error{Provider: zone.Provider.Kind(), Operation: "acme_challenge", Code: dnsgo.CodeConflict,
				Message: "matching TXT record has no ID or is disabled"}
		}
		tracked.RecordID = existing.ID
		if observer, ok := s.observer.(ChallengeReuseObserver); ok {
			if err := observer.Reused(ctx, tracked); err != nil {
				return err
			}
		}
		s.mu.Lock()
		s.created[challenge.URL] = challengeRecord{zone: zone, record: existing, name: name, owned: false}
		s.mu.Unlock()
		return nil
	}
	if s.observer != nil {
		if err := s.observer.BeforeCreate(ctx, tracked); err != nil {
			return err
		}
	}
	ttl := 600
	if min, err := zone.Provider.MinTTL(ctx, zone.ID); err == nil && min > ttl {
		ttl = min
	}
	record, err := zone.Provider.CreateRecord(ctx, zone.ID, dnsgo.Record{Name: relative, Type: "TXT", Value: value, TTL: ttl})
	if record.ID != "" {
		tracked.RecordID = record.ID
		s.mu.Lock()
		s.created[challenge.URL] = challengeRecord{zone: zone, record: record, name: name, owned: true}
		s.mu.Unlock()
		if s.observer != nil {
			if observerErr := s.observer.Created(ctx, tracked); observerErr != nil {
				return observerErr
			}
		}
	}
	if err != nil {
		return err
	}
	if record.ID == "" {
		return &dnsgo.Error{Provider: zone.Provider.Kind(), Operation: "acme_challenge", Code: dnsgo.CodeResultUnknown,
			Message: "provider did not return an ID for the created TXT record"}
	}
	return nil
}

func (s *dnsSolver) Wait(ctx context.Context, challenge acme.Challenge) error {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	name := canonicalDomain(challenge.DNS01TXTRecordName())
	wanted := challenge.DNS01KeyAuthorization()
	ticker := time.NewTicker(s.poll)
	defer ticker.Stop()
	for {
		values, err := net.DefaultResolver.LookupTXT(ctx, name)
		if err == nil {
			for _, value := range values {
				if value == wanted {
					return nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("ACME DNS challenge did not propagate for %s: %w", name, ctx.Err())
		case <-ticker.C:
		}
	}
}

func (s *dnsSolver) CleanUp(ctx context.Context, challenge acme.Challenge) error {
	s.mu.Lock()
	created, ok := s.created[challenge.URL]
	s.mu.Unlock()
	if !ok {
		return nil
	}
	if created.owned {
		if err := created.zone.Provider.DeleteRecord(ctx, created.zone.ID, created.record.ID); err != nil && !dnsgo.IsCode(err, dnsgo.CodeNotFound) {
			return err
		}
	}
	_, reuseObserved := s.observer.(ChallengeReuseObserver)
	if s.observer != nil && (created.owned || reuseObserved) {
		tracked := ChallengeRecord{ChallengeURL: challenge.URL, Provider: created.zone.Provider.Kind(), ZoneID: created.zone.ID,
			Name: created.name, Type: "TXT", Value: challenge.DNS01KeyAuthorization(), RecordID: created.record.ID}
		if err := s.observer.Removed(ctx, tracked); err != nil {
			return err
		}
	}
	s.mu.Lock()
	delete(s.created, challenge.URL)
	s.mu.Unlock()
	return nil
}
