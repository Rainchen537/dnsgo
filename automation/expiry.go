package automation

import (
	"context"
	"sort"
	"time"
)

type DomainExpiry struct {
	Name         string
	RegisteredAt time.Time
	ExpiresAt    time.Time
	LastChecked  time.Time
	LastNotified time.Time
	Notify       bool
}

type ExpiryLookup interface {
	LookupDomain(context.Context, string) (registeredAt, expiresAt time.Time, err error)
}

type ExpiryGroup struct {
	Days    int
	Domains []DomainExpiry
}

// RefreshExpiry updates registration and expiry dates from a caller-provided
// WHOIS or RDAP lookup. A failed lookup preserves the last known expiry.
func RefreshExpiry(ctx context.Context, lookup ExpiryLookup, domain DomainExpiry, now time.Time) (DomainExpiry, error) {
	registered, expires, err := lookup.LookupDomain(ctx, domain.Name)
	domain.LastChecked = now
	if err != nil {
		return domain, err
	}
	if !registered.IsZero() {
		domain.RegisteredAt = registered
	}
	if !expires.IsZero() {
		domain.ExpiresAt = expires
	}
	return domain, nil
}

// DueExpiryGroups follows the reference's day thresholds, 20-hour notice
// cooldown and 09:00 local send window. Callers persist LastNotified after a
// notification channel confirms delivery.
func DueExpiryGroups(domains []DomainExpiry, days []int, now time.Time) []ExpiryGroup {
	if now.Hour() < 9 || len(days) == 0 {
		return nil
	}
	thresholds := map[int]bool{}
	for _, day := range days {
		if day >= 0 {
			thresholds[day] = true
		}
	}
	groups := map[int][]DomainExpiry{}
	for _, domain := range domains {
		if !domain.Notify || domain.Name == "" || domain.ExpiresAt.IsZero() || domain.ExpiresAt.Before(now) {
			continue
		}
		if !domain.LastNotified.IsZero() && now.Sub(domain.LastNotified) < 20*time.Hour {
			continue
		}
		day := int(domain.ExpiresAt.Sub(now).Hours() / 24)
		if thresholds[day] {
			groups[day] = append(groups[day], domain)
		}
	}
	keys := make([]int, 0, len(groups))
	for day := range groups {
		keys = append(keys, day)
	}
	sort.Ints(keys)
	result := make([]ExpiryGroup, 0, len(keys))
	for _, day := range keys {
		sort.Slice(groups[day], func(i, j int) bool {
			return groups[day][i].ExpiresAt.Before(groups[day][j].ExpiresAt)
		})
		result = append(result, ExpiryGroup{Days: day, Domains: groups[day]})
	}
	return result
}
