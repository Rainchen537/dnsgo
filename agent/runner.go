package agent

import (
	"context"
	"errors"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rainchen537/dnsgo"
	"github.com/rainchen537/dnsgo/automation"
	"github.com/rainchen537/dnsgo/cert"
	"github.com/rainchen537/dnsgo/deploy"
	"github.com/rainchen537/dnsgo/notify"
	"github.com/rainchen537/dnsgo/providers"
)

type Runner struct {
	Config       Config
	Store        *Store
	DNS          map[string]dnsgo.Provider
	Notify       notify.Dispatcher
	Lookup       automation.ExpiryLookup
	Now          func() time.Time
	OnError      func(error)
	probeClients map[string]*http.Client
}

func NewRunner(config Config, store *Store) (*Runner, error) {
	if store == nil {
		return nil, fmt.Errorf("SQLite store is required")
	}
	r := &Runner{Config: config, Store: store, DNS: map[string]dnsgo.Provider{},
		Lookup: automation.RegistrationLookup{RDAP: &automation.RDAPLookup{}}, Now: time.Now,
		probeClients: map[string]*http.Client{}}
	r.Config.Expiry.Domains = append([]string(nil), config.Expiry.Domains...)
	for name, profile := range config.Providers {
		httpClient, err := proxyHTTPClient(profile.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("provider profile %s proxy: %w", name, err)
		}
		provider, err := providers.New(profile.Kind, dnsgo.Config{Credentials: profile.Credentials,
			Domain: profile.Domain, DomainID: profile.DomainID, Endpoint: profile.Endpoint, HTTPClient: httpClient})
		if err != nil {
			return nil, fmt.Errorf("provider profile %s: %w", name, err)
		}
		r.DNS[name] = &synchronizedProvider{Provider: provider}
	}
	seen := map[string]bool{}
	ownedRecords := map[string]string{}
	failoverByID := map[string]FailoverConfig{}
	for _, task := range config.Failovers {
		failoverByID[task.ID] = task
		if err := uniqueTask(seen, "failover", task.ID); err != nil {
			return nil, err
		}
		if r.DNS[task.Provider] == nil {
			return nil, fmt.Errorf("failover %s references unknown provider %s", task.ID, task.Provider)
		}
		if task.Mode == automation.FailoverConditional && len(task.Siblings) == 0 {
			return nil, fmt.Errorf("conditional failover %s needs sibling task IDs", task.ID)
		}
		if task.ZoneID == "" || task.RecordID == "" {
			return nil, fmt.Errorf("failover %s needs zone and record IDs", task.ID)
		}
		if task.ProxyOnBackup && r.DNS[task.Provider].Kind() != "cloudflare" {
			return nil, fmt.Errorf("failover %s proxy_on_backup requires Cloudflare", task.ID)
		}
		if task.Mode == automation.FailoverValue &&
			(task.PrimaryValue == "" || task.BackupValue == "" || task.PrimaryValue == task.BackupValue) {
			return nil, fmt.Errorf("failover %s needs distinct primary and backup values", task.ID)
		}
		if (task.Mode == automation.FailoverPause || task.Mode == automation.FailoverConditional) &&
			!r.DNS[task.Provider].Capabilities().Status {
			return nil, fmt.Errorf("failover %s provider does not support record status", task.ID)
		}
		if err := reserveRecord(ownedRecords, task.Provider, task.ZoneID, task.RecordID, "failover "+task.ID); err != nil {
			return nil, err
		}
		switch task.Mode {
		case automation.FailoverPause, automation.FailoverValue:
			if err := validateProbeConfig(task.Probe); err != nil {
				return nil, fmt.Errorf("failover %s: %w", task.ID, err)
			}
			httpClient, err := proxyHTTPClient(task.Probe.ProxyURL)
			if err != nil {
				return nil, fmt.Errorf("failover %s proxy: %w", task.ID, err)
			}
			r.probeClients[task.ID] = httpClient
		case automation.FailoverConditional:
		default:
			return nil, fmt.Errorf("failover %s has invalid mode", task.ID)
		}
	}
	for _, task := range config.Failovers {
		if task.Mode != automation.FailoverConditional {
			continue
		}
		siblings := map[string]bool{}
		for _, id := range task.Siblings {
			sibling, exists := failoverByID[id]
			if id == task.ID || !exists || siblings[id] || sibling.Probe.Kind == "" {
				return nil, fmt.Errorf("conditional failover %s has invalid sibling %s", task.ID, id)
			}
			siblings[id] = true
		}
	}
	for _, task := range config.Schedules {
		if err := uniqueTask(seen, "schedule", task.ID); err != nil {
			return nil, err
		}
		if r.DNS[task.Provider] == nil {
			return nil, fmt.Errorf("schedule %s references unknown provider %s", task.ID, task.Provider)
		}
		if err := reserveRecord(ownedRecords, task.Provider, task.ZoneID, task.RecordID, "schedule "+task.ID); err != nil {
			return nil, err
		}
		schedule, err := task.automation()
		if err != nil {
			return nil, err
		}
		if _, err := automation.InitSchedule(schedule, time.Now()); err != nil {
			return nil, fmt.Errorf("schedule %s: %w", task.ID, err)
		}
	}
	targetNames := map[string]bool{}
	for _, name := range deploy.Names() {
		targetNames[name] = true
	}
	for _, task := range config.Certificates {
		if err := uniqueTask(seen, "certificate", task.ID); err != nil {
			return nil, err
		}
		if len(task.Domains) == 0 && task.Authority != "manual" {
			return nil, fmt.Errorf("certificate %s needs domains", task.ID)
		}
		if task.Authority == "" {
			return nil, fmt.Errorf("certificate %s needs authority", task.ID)
		}
		certificateHTTP, err := proxyHTTPClient(task.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("certificate %s proxy: %w", task.ID, err)
		}
		if task.Authority == "manual" {
			if !filepath.IsAbs(task.CertFile) || !filepath.IsAbs(task.KeyFile) || task.CertFile == task.KeyFile {
				return nil, fmt.Errorf("manual certificate %s needs distinct absolute cert_file and key_file", task.ID)
			}
		} else if task.Email == "" {
			return nil, fmt.Errorf("certificate %s needs email", task.ID)
		}
		if task.Authority != "manual" && len(task.Zones) == 0 {
			return nil, fmt.Errorf("certificate %s needs at least one DNS zone binding", task.ID)
		}
		if isACME(task.Authority) {
			if cert.Authority(task.Authority) == cert.CustomACME && task.Directory == "" {
				return nil, fmt.Errorf("certificate %s needs custom ACME directory", task.ID)
			}
		} else if task.Authority != "manual" {
			_, err := cloudIssuer(task, certificateHTTP)
			if err != nil {
				return nil, fmt.Errorf("certificate %s: %w", task.ID, err)
			}
		}
		for _, zone := range task.Zones {
			if strings.Trim(zone.Name, ". ") == "" || zone.ID == "" {
				return nil, fmt.Errorf("certificate %s has an incomplete DNS zone binding", task.ID)
			}
			if r.DNS[zone.Provider] == nil {
				return nil, fmt.Errorf("certificate %s references unknown DNS provider %s", task.ID, zone.Provider)
			}
		}
		if isACME(task.Authority) {
			for _, domain := range task.Domains {
				name := strings.Trim(strings.ToLower(strings.TrimPrefix(domain, "*.")), ".")
				challengeName := "_acme-challenge." + name
				for source, alias := range task.ChallengeAliases {
					if strings.EqualFold(strings.Trim(source, "."), challengeName) && alias != "" {
						challengeName = strings.Trim(strings.ToLower(alias), ".")
						break
					}
				}
				covered := false
				for _, zone := range task.Zones {
					zoneName := strings.Trim(strings.ToLower(zone.Name), ".")
					if challengeName == zoneName || strings.HasSuffix(challengeName, "."+zoneName) {
						covered = true
						break
					}
				}
				if !covered {
					return nil, fmt.Errorf("certificate %s has no DNS zone binding for %s", task.ID, challengeName)
				}
			}
		}
		validationDomains := task.Domains
		if task.Authority == "manual" && len(validationDomains) == 0 {
			// Construction is local validation only. The actual manual certificate
			// supplies its parsed DNS names when deployment runs.
			validationDomains = []string{"dnsgo.invalid"}
		}
		for _, target := range task.Deployments {
			if err := uniqueTask(seen, "deployment:"+task.ID, target.ID); err != nil {
				return nil, err
			}
			if !targetNames[target.Target] {
				return nil, fmt.Errorf("certificate %s has unknown deployment target %s", task.ID, target.Target)
			}
			httpClient, err := proxyHTTPClient(target.ProxyURL)
			if err != nil {
				return nil, fmt.Errorf("certificate %s deployment %s proxy: %w", task.ID, target.ID, err)
			}
			if _, err := deploy.New(target.Target, deploy.Config{Values: target.Values, Domains: validationDomains, Endpoint: target.Endpoint, HTTPClient: httpClient}); err != nil {
				return nil, fmt.Errorf("certificate %s deployment %s: %w", task.ID, target.ID, err)
			}
		}
	}
	for _, n := range config.Notifications {
		if err := uniqueTask(seen, "notification", n.ID); err != nil {
			return nil, err
		}
		channel, err := notificationChannel(n)
		if err != nil {
			return nil, fmt.Errorf("notification %s: %w", n.ID, err)
		}
		for _, policy := range []string{n.Failover, n.Cert, n.Expiry} {
			if policy != "" && policy != string(notify.PolicyAll) && policy != string(notify.PolicyFailures) && policy != string(notify.PolicyOff) {
				return nil, fmt.Errorf("notification %s has invalid policy %q", n.ID, policy)
			}
		}
		r.Notify.Routes = append(r.Notify.Routes, notify.Route{ID: n.ID, Channel: channel,
			Failover: notify.Policy(n.Failover), Cert: notify.Policy(n.Cert), Expiry: notify.Policy(n.Expiry)})
	}
	expiryNames := map[string]bool{}
	for index, name := range r.Config.Expiry.Domains {
		registered, err := automation.RegisteredDomain(name)
		if err != nil {
			return nil, fmt.Errorf("expiry domain %q: %w", name, err)
		}
		if !strings.EqualFold(strings.Trim(name, "."), registered) {
			return nil, fmt.Errorf("expiry domain %q must be a registrable domain, not a subdomain", name)
		}
		if expiryNames[registered] {
			return nil, fmt.Errorf("duplicate expiry domain %s", registered)
		}
		expiryNames[registered] = true
		r.Config.Expiry.Domains[index] = registered
	}
	return r, nil
}

func uniqueTask(seen map[string]bool, kind, id string) error {
	if id == "" {
		return fmt.Errorf("%s task ID is required", kind)
	}
	key := kind + ":" + id
	if seen[key] {
		return fmt.Errorf("duplicate %s task ID %s", kind, id)
	}
	seen[key] = true
	return nil
}

func validateProbeConfig(probe ProbeConfig) error {
	if probe.ProxyURL != "" && probe.Kind != automation.ProbeHTTP {
		return fmt.Errorf("probe proxy is supported only for HTTP(S) checks")
	}
	if probe.IP != "" && net.ParseIP(probe.IP) == nil {
		return fmt.Errorf("probe direct IP is invalid")
	}
	switch probe.Kind {
	case automation.ProbePing:
		if probe.Target == "" && probe.IP == "" {
			return fmt.Errorf("ping probe needs a target")
		}
	case automation.ProbeTCP:
		if (probe.Target == "" && probe.IP == "") || probe.Port < 1 || probe.Port > 65535 {
			return fmt.Errorf("TCP probe needs a target and valid port")
		}
	case automation.ProbeHTTP:
		parsed, err := url.Parse(probe.Target)
		if err != nil || parsed.Host == "" || parsed.Scheme != "http" && parsed.Scheme != "https" {
			return fmt.Errorf("HTTP probe needs an HTTP(S) URL")
		}
	default:
		return fmt.Errorf("invalid probe kind")
	}
	return nil
}

func reserveRecord(owners map[string]string, profile, zone, record, task string) error {
	key := profile + "\x00" + zone + "\x00" + record
	if prior := owners[key]; prior != "" {
		return fmt.Errorf("%s and %s both write the same DNS record", prior, task)
	}
	owners[key] = task
	return nil
}

func notificationChannel(config NotificationConfig) (notify.Channel, error) {
	v := config.Values
	httpClient, err := proxyHTTPClient(config.ProxyURL)
	if err != nil {
		return nil, err
	}
	switch config.Type {
	case "smtp":
		if httpClient != nil {
			return nil, fmt.Errorf("SMTP notification does not support an HTTP proxy")
		}
		port, err := strconv.Atoi(v["port"])
		if err != nil {
			return nil, fmt.Errorf("SMTP port is required")
		}
		return notify.SMTP{Host: v["host"], Port: port, User: v["user"], Password: v["password"],
			From: v["from"], To: v["to"], FromName: v["from_name"]}, nil
	case "sendcloud":
		return notify.SendCloud{APIUser: v["api_user"], APIKey: v["api_key"], From: v["from"], To: v["to"], FromName: v["from_name"], Client: httpClient}, nil
	case "aliyun_directmail":
		return notify.AliyunDirectMail{KeyID: v["key_id"], Secret: v["secret"], From: v["from"], To: v["to"], FromName: v["from_name"], Client: httpClient}, nil
	case "wxpusher":
		return notify.WXPusher{AppToken: v["app_token"], UID: v["uid"], Client: httpClient}, nil
	case "telegram":
		topic, _ := strconv.ParseInt(v["topic_id"], 10, 64)
		return notify.Telegram{Token: v["token"], ChatID: v["chat_id"], TopicID: topic, BaseURL: v["base_url"], Client: httpClient}, nil
	case "qqbot":
		return &notify.QQBot{AppID: v["app_id"], AppSecret: v["app_secret"], OpenID: v["open_id"], Client: httpClient}, nil
	case "webhook":
		return notify.Webhook{URL: v["url"], AtUsers: v["at_users"], Client: httpClient}, nil
	case "custom_webhook":
		headers := http.Header{}
		for _, line := range strings.Split(v["headers"], "\n") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				headers.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
			}
		}
		return notify.CustomWebhook{URL: v["url"], Method: v["method"], ContentType: v["content_type"],
			Format: v["format"], BodyTemplate: v["body"], Headers: headers, Client: httpClient}, nil
	default:
		return nil, fmt.Errorf("unknown notification type %q", config.Type)
	}
}

func (r *Runner) Tick(ctx context.Context) error {
	now := r.Now()
	var failures []error
	if err := r.failovers(ctx, now); err != nil {
		failures = append(failures, err)
	}
	if err := r.schedules(ctx, now); err != nil {
		failures = append(failures, err)
	}
	if err := r.certificates(ctx, now); err != nil {
		failures = append(failures, err)
	}
	if err := r.expiry(ctx, now); err != nil {
		failures = append(failures, err)
	}
	if err := r.deliverPending(ctx); err != nil {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}

func (r *Runner) Run(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	interval := time.Duration(r.Config.Interval) * time.Second
	if interval <= 0 {
		interval = time.Minute
	}
	var workers sync.WaitGroup
	var reportMu sync.Mutex
	start := func(name string, work func(context.Context, time.Time) error) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				if ctx.Err() != nil {
					return
				}
				if err := work(ctx, r.Now()); err != nil && ctx.Err() == nil && r.OnError != nil {
					reportMu.Lock()
					r.OnError(fmt.Errorf("%s: %w", name, err))
					reportMu.Unlock()
				}
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
			}
		}()
	}
	start("failover", r.failovers)
	start("schedule", r.schedules)
	start("certificate", r.certificates)
	start("expiry", r.expiry)
	start("notification", func(ctx context.Context, _ time.Time) error { return r.deliverPending(ctx) })
	<-ctx.Done()
	workers.Wait()
	return ctx.Err()
}

func (r *Runner) deliverPending(ctx context.Context) error {
	items, err := r.Store.PendingEvents(ctx)
	if err != nil {
		return err
	}
	var failures []error
	for _, item := range items {
		delivered, sendErr := r.Notify.Deliver(ctx, item.Event, item.Delivered)
		item.Delivered = delivered
		if err := r.Store.SavePendingEvent(ctx, item); err != nil {
			failures = append(failures, fmt.Errorf("persist notification delivery: %w", err))
			continue
		}
		if sendErr != nil {
			failures = append(failures, fmt.Errorf("pending notification %s: %w", item.ID, sendErr))
			continue
		}
		if err := r.Store.Delete(ctx, "outbox", item.ID); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (r *Runner) failovers(ctx context.Context, now time.Time) error {
	probes := map[string]automation.ProbeResult{}
	byID := map[string]FailoverConfig{}
	for _, task := range r.Config.Failovers {
		byID[task.ID] = task
		if task.Probe.Kind != "" {
			probe := task.Probe.automation()
			probe.HTTPClient = r.probeClients[task.ID]
			probes[task.ID] = automation.Probe(ctx, probe)
		}
	}
	var failures []error
	for _, config := range r.Config.Failovers {
		var state automation.FailoverState
		found, err := r.Store.Load(ctx, "failover", config.ID, &state)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if !found {
			current, err := r.DNS[config.Provider].GetRecord(ctx, config.ZoneID, config.RecordID)
			if err != nil {
				failures = append(failures, fmt.Errorf("failover %s initial readback: %w", config.ID, err))
				continue
			}
			if current.ID != "" {
				state.RecordID = current.ID
			}
			switch config.Mode {
			case automation.FailoverPause:
				if current.Enabled == nil {
					failures = append(failures, fmt.Errorf("failover %s initial record status is unknown", config.ID))
					continue
				}
				state.BackupActive = !*current.Enabled
			case automation.FailoverConditional:
				if current.Enabled == nil {
					failures = append(failures, fmt.Errorf("failover %s initial record status is unknown", config.ID))
					continue
				}
				state.ConditionalEnabled = *current.Enabled
			case automation.FailoverValue:
				if current.Value != config.PrimaryValue && current.Value != config.BackupValue {
					failures = append(failures, fmt.Errorf("failover %s initial record value matches neither configured value", config.ID))
					continue
				}
				state.BackupActive = current.Value == config.BackupValue
			}
			if err := r.Store.Save(ctx, "failover", config.ID, state); err != nil {
				failures = append(failures, err)
				continue
			}
		}
		if state.InFlight {
			next, transition, err := reconcileFailover(ctx, r.DNS[config.Provider], config, state, now)
			if err != nil {
				failures = append(failures, fmt.Errorf("failover %s reconciliation: %w", config.ID, err))
				continue
			}
			if err := r.Store.SaveWithEvent(ctx, "failover", config.ID, next, failoverEvent(config, transition)); err != nil {
				failures = append(failures, fmt.Errorf("failover %s state: %w", config.ID, err))
			}
			continue
		}
		var next automation.FailoverState
		var transition automation.Transition
		writeAttempted := false
		provider := failoverIntentProvider{Provider: r.DNS[config.Provider]}
		intent := func(backup, enabled bool) error {
			pending := pendingFailover(state, config, now, backup, enabled,
				provider.Kind() == "cloudflare")
			if err := r.Store.Save(ctx, "failover", config.ID, pending); err != nil {
				return err
			}
			writeAttempted = true
			return nil
		}
		if config.Mode == automation.FailoverConditional {
			healthy := 0
			for _, id := range config.Siblings {
				if _, exists := byID[id]; !exists {
					err = fmt.Errorf("unknown sibling %s", id)
					break
				}
				probe, exists := probes[id]
				if !exists {
					err = fmt.Errorf("sibling %s has no probe", id)
					break
				}
				if probe.Healthy {
					healthy++
				}
			}
			if err == nil {
				provider.beforeWrite = func() error { return intent(false, healthy <= config.Cycle) }
				next, transition, err = automation.EvaluateConditional(ctx, provider, config.automation(), state, healthy)
			}
		} else {
			probe, exists := probes[config.ID]
			if !exists {
				err = fmt.Errorf("probe configuration is required")
			} else {
				provider.beforeWrite = func() error { return intent(!probe.Healthy, false) }
				next, transition, err = automation.EvaluateFailover(ctx, provider, config.automation(), state, probe)
			}
		}
		if err != nil {
			failures = append(failures, fmt.Errorf("failover %s: %w", config.ID, err))
			continue
		}
		if writeAttempted {
			clearFailoverIntent(&next)
		}
		if transition.Changed {
			err = r.Store.SaveWithEvent(ctx, "failover", config.ID, next, failoverEvent(config, transition))
		} else {
			err = r.Store.Save(ctx, "failover", config.ID, next)
		}
		if err != nil {
			failures = append(failures, fmt.Errorf("failover %s state: %w", config.ID, err))
		}
	}
	return errors.Join(failures...)
}

func failoverEvent(config FailoverConfig, transition automation.Transition) notify.Event {
	return notify.Event{Kind: notify.Failover, Success: transition.Action == "primary" || transition.Action == "disable",
		Title: "DNS 故障切换：" + config.ID + " → " + transition.Action,
		HTML:  "记录 " + html.EscapeString(transition.RecordID) + " 已执行 " + html.EscapeString(transition.Action)}
}

func (r *Runner) schedules(ctx context.Context, now time.Time) error {
	var failures []error
	for _, config := range r.Config.Schedules {
		task, err := config.automation()
		if err != nil {
			failures = append(failures, err)
			continue
		}
		var state automation.ScheduleState
		exists, err := r.Store.Load(ctx, "schedule", config.ID, &state)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if !exists {
			state, err = automation.InitSchedule(task, now)
			if err != nil {
				failures = append(failures, err)
				continue
			}
			if err := r.Store.Save(ctx, "schedule", config.ID, state); err != nil {
				failures = append(failures, err)
				continue
			}
		}
		if state.Completed {
			continue
		}
		if state.InFlight {
			if state.IntentKey != "" && state.IntentKey != scheduleIntentKey(task, state) {
				failures = append(failures, fmt.Errorf("schedule %s configuration changed during an in-flight DNS write", config.ID))
				continue
			}
			reconciled, done, err := automation.ReconcileDueSchedule(ctx, r.DNS[config.Provider], task, state, now)
			if err != nil {
				failures = append(failures, fmt.Errorf("schedule %s reconciliation: %w", config.ID, err))
				continue
			}
			if done {
				if err := r.Store.Save(ctx, "schedule", config.ID, reconciled); err != nil {
					failures = append(failures, err)
				}
				continue
			}
			failures = append(failures, fmt.Errorf("schedule %s has an unconfirmed prior DNS write; inspect it before retrying", config.ID))
			continue
		}
		if now.Before(state.NextRun) {
			continue
		}
		state.InFlight = true
		state.AttemptAt = now
		state.IntentKey = scheduleIntentKey(task, state)
		if err := r.Store.Save(ctx, "schedule", config.ID, state); err != nil {
			failures = append(failures, err)
			continue
		}
		next, _, err := automation.RunDueSchedule(ctx, r.DNS[config.Provider], task, state, now)
		if err != nil {
			failures = append(failures, fmt.Errorf("schedule %s: %w", config.ID, err))
			continue
		}
		if err := r.Store.Save(ctx, "schedule", config.ID, next); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}
