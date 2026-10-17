package automation

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"time"
)

// WHOISLookup is a fallback for TLDs absent from the IANA RDAP bootstrap or
// servers that omit an expiration event. WHOIS output is not standardized.
type WHOISLookup struct {
	Timeout time.Duration
}

var whoisHostPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$`)

func (w WHOISLookup) query(ctx context.Context, host, name string) (string, error) {
	if !whoisHostPattern.MatchString(host) {
		return "", fmt.Errorf("invalid WHOIS server name")
	}
	timeout := w.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, "43"))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := io.WriteString(conn, name+"\r\n"); err != nil {
		return "", err
	}
	data, err := io.ReadAll(io.LimitReader(conn, 2<<20))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func whoisField(body string, keys ...string) string {
	wanted := map[string]bool{}
	for _, key := range keys {
		wanted[strings.ToLower(key)] = true
	}
	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 && wanted[strings.ToLower(strings.TrimSpace(parts[0]))] {
			return strings.TrimSpace(parts[1])
		}
	}
	return ""
}

func whoisDate(raw string) time.Time {
	raw = strings.TrimSpace(raw)
	for _, layout := range []string{
		time.RFC3339, "2006-01-02T15:04:05Z", "2006-01-02T15:04:05.000Z",
		"2006-01-02 15:04:05", "2006-01-02", "02-Jan-2006", "02-Jan-2006 15:04:05 MST",
		"2006.01.02", "02/01/2006", "Jan 2 2006", "2006/01/02",
	} {
		if parsed, err := time.Parse(layout, raw); err == nil {
			return parsed
		}
	}
	return time.Time{}
}

func (w WHOISLookup) LookupDomain(ctx context.Context, name string) (time.Time, time.Time, error) {
	domain, err := domainForLookup(name)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	labels := strings.Split(domain, ".")
	tld := labels[len(labels)-1]
	iana, err := w.query(ctx, "whois.iana.org", tld)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("IANA WHOIS discovery failed: %w", err)
	}
	server := whoisField(iana, "whois")
	if server == "" {
		return time.Time{}, time.Time{}, fmt.Errorf("IANA has no WHOIS server for %s", tld)
	}
	response, err := w.query(ctx, server, domain)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("WHOIS query failed: %w", err)
	}
	registered := whoisDate(whoisField(response, "Creation Date", "Created Date", "Created On", "Registration Date", "created"))
	expires := whoisDate(whoisField(response, "Registry Expiry Date", "Registrar Registration Expiration Date", "Expiration Date", "Expiry Date", "expires", "paid-till"))
	if expires.IsZero() {
		return registered, expires, fmt.Errorf("WHOIS response has no recognized expiry date")
	}
	return registered, expires, nil
}

// RegistrationLookup uses RDAP first, then WHOIS when the RDAP result is not
// usable. The caller should persist previous dates when both sources fail.
type RegistrationLookup struct {
	RDAP  *RDAPLookup
	WHOIS WHOISLookup
}

func (r RegistrationLookup) LookupDomain(ctx context.Context, name string) (time.Time, time.Time, error) {
	rdap := r.RDAP
	if rdap == nil {
		rdap = &RDAPLookup{}
	}
	registered, expires, firstErr := rdap.LookupDomain(ctx, name)
	if firstErr == nil {
		return registered, expires, nil
	}
	registered, expires, secondErr := r.WHOIS.LookupDomain(ctx, name)
	if secondErr == nil {
		return registered, expires, nil
	}
	return time.Time{}, time.Time{}, fmt.Errorf("RDAP: %v; WHOIS: %w", firstErr, secondErr)
}
