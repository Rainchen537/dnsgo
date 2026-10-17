// Package notify delivers DnsGo automation events through the notification
// channels present in the Rainbow DNS reference project.
package notify

import (
	"context"
	"errors"
	"fmt"
	"html"
	"regexp"
	"strings"
)

type Kind string

const (
	Failover   Kind = "failover"
	CertOrder  Kind = "cert_order"
	CertDeploy Kind = "cert_deploy"
	Expiry     Kind = "expiry"
)

type Event struct {
	Kind    Kind
	Title   string
	HTML    string
	Success bool
}

// Text converts the reference project's simple HTML notification templates
// into plain text without treating arbitrary HTML as Markdown.
func (e Event) Text() string {
	s := strings.NewReplacer("<br/>", "\n", "<br>", "\n", "<br />", "\n", "</p>", "\n").Replace(e.HTML)
	s = regexp.MustCompile(`<[^>]*>`).ReplaceAllString(s, "")
	return html.UnescapeString(s)
}

type Channel interface {
	Name() string
	Send(context.Context, Event) error
}

type Policy string

const (
	PolicyOff      Policy = "off"
	PolicyAll      Policy = "all"
	PolicyFailures Policy = "failures"
)

type Route struct {
	ID       string
	Channel  Channel
	Failover Policy
	Cert     Policy
	Expiry   Policy
}

type Dispatcher struct{ Routes []Route }

func (d Dispatcher) Send(ctx context.Context, event Event) error {
	_, err := d.Deliver(ctx, event, nil)
	return err
}

// Deliver records successful channel IDs so a persistent outbox can retry
// only channels that have not confirmed delivery. A delivery can still happen
// twice if the process exits after the remote accepts it but before saving.
func (d Dispatcher) Deliver(ctx context.Context, event Event, delivered map[string]bool) (map[string]bool, error) {
	if event.Title == "" {
		return delivered, fmt.Errorf("notification title is required")
	}
	if delivered == nil {
		delivered = map[string]bool{}
	}
	var failures []error
	for index, route := range d.Routes {
		if route.Channel == nil {
			continue
		}
		id := route.ID
		if id == "" {
			id = fmt.Sprintf("%d:%s", index, route.Channel.Name())
		}
		if delivered[id] {
			continue
		}
		policy := route.Cert
		switch event.Kind {
		case Failover:
			policy = route.Failover
		case CertOrder, CertDeploy:
		case Expiry:
			policy = route.Expiry
		default:
			return delivered, fmt.Errorf("unknown notification kind %q", event.Kind)
		}
		if policy == PolicyOff || policy == "" || policy == PolicyFailures && event.Success {
			continue
		}
		if policy != PolicyAll && policy != PolicyFailures {
			return delivered, fmt.Errorf("invalid notification policy for %s", route.Channel.Name())
		}
		if err := route.Channel.Send(ctx, event); err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", route.Channel.Name(), err))
		} else {
			delivered[id] = true
		}
	}
	return delivered, errors.Join(failures...)
}
