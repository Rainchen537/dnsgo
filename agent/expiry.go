package agent

import (
	"context"
	"errors"
	"fmt"
	"html"
	"strings"
	"time"

	"github.com/rainchen537/dnsgo/automation"
	"github.com/rainchen537/dnsgo/notify"
)

func (r *Runner) expiry(ctx context.Context, now time.Time) error {
	if len(r.Config.Expiry.Domains) == 0 {
		return nil
	}
	if r.Lookup == nil {
		return fmt.Errorf("domain registration lookup is required")
	}
	maxDay := 30
	for _, day := range r.Config.Expiry.Days {
		if day+1 > maxDay {
			maxDay = day + 1
		}
	}
	domains := make([]automation.DomainExpiry, 0, len(r.Config.Expiry.Domains))
	var failures []error
	refreshed := 0
	for _, name := range r.Config.Expiry.Domains {
		if name == "" {
			continue
		}
		var domain automation.DomainExpiry
		found, err := r.Store.Load(ctx, "expiry", name, &domain)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if !found {
			domain = automation.DomainExpiry{Name: name, Notify: true}
		}
		if domain.Name != name {
			return fmt.Errorf("expiry state key mismatch for %s", name)
		}
		refresh := domain.LastChecked.IsZero() ||
			(!domain.ExpiresAt.IsZero() && domain.ExpiresAt.After(now.Add(-5*24*time.Hour)) &&
				domain.ExpiresAt.Before(now.Add(time.Duration(maxDay)*24*time.Hour)) &&
				now.Sub(domain.LastChecked) >= 24*time.Hour)
		if refresh && refreshed < 5 {
			domain, err = automation.RefreshExpiry(ctx, r.Lookup, domain, now)
			if err != nil {
				failures = append(failures, fmt.Errorf("expiry lookup %s: %w", name, err))
			}
			if saveErr := r.Store.Save(ctx, "expiry", name, domain); saveErr != nil {
				failures = append(failures, saveErr)
			}
			refreshed++
		}
		domains = append(domains, domain)
	}
	if refreshed > 0 {
		return errors.Join(failures...)
	}
	for _, group := range automation.DueExpiryGroups(domains, r.Config.Expiry.Days, now) {
		states := make(map[string]any, len(group.Domains))
		lines := make([]string, 0, len(group.Domains))
		for _, domain := range group.Domains {
			domain.LastNotified = now
			states[domain.Name] = domain
			lines = append(lines, html.EscapeString(domain.Name)+" - "+html.EscapeString(domain.ExpiresAt.Format(time.RFC3339)))
		}
		event := notify.Event{Kind: notify.Expiry, Success: false,
			Title: fmt.Sprintf("%d 个域名将在 %d 天后到期", len(group.Domains), group.Days),
			HTML:  strings.Join(lines, "<br/>")}
		if err := r.Store.SaveManyWithEvent(ctx, "expiry", states, event); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}
