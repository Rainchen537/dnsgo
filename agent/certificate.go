package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rainchen537/dnsgo"
	"github.com/rainchen537/dnsgo/cert"
	"github.com/rainchen537/dnsgo/deploy"
	"github.com/rainchen537/dnsgo/notify"
)

type challengeRecord struct {
	ChallengeURL string
	ZoneID       string
	Provider     string
	RecordID     string
	Name         string
	Type         string
	Value        string
	Owned        bool
}

type acmeChallengeObserver struct {
	mu     sync.Mutex
	runner *Runner
	id     string
	state  *certificateState
}

func (o *acmeChallengeObserver) BeforeCreate(ctx context.Context, value cert.ChallengeRecord) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, existing := range o.state.Challenges {
		if existing.ChallengeURL == value.ChallengeURL {
			return &dnsgo.Error{Provider: value.Provider, Operation: "acme_challenge", Code: dnsgo.CodeConflict,
				Message: "challenge already has a pending DNS write"}
		}
	}
	o.state.Challenges = append(o.state.Challenges, challengeRecord{ChallengeURL: value.ChallengeURL,
		Provider: value.Provider, ZoneID: value.ZoneID, Name: value.Name, Type: value.Type, Value: value.Value, Owned: true})
	if err := o.runner.Store.Save(ctx, "certificate", o.id, o.state); err != nil {
		o.state.Challenges = o.state.Challenges[:len(o.state.Challenges)-1]
		return err
	}
	return nil
}

func (o *acmeChallengeObserver) Created(ctx context.Context, value cert.ChallengeRecord) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	for index := range o.state.Challenges {
		if o.state.Challenges[index].ChallengeURL == value.ChallengeURL {
			o.state.Challenges[index].RecordID = value.RecordID
			return o.runner.Store.Save(ctx, "certificate", o.id, o.state)
		}
	}
	return &dnsgo.Error{Provider: value.Provider, Operation: "acme_challenge", Code: dnsgo.CodeResultUnknown,
		Message: "created challenge has no stored intent"}
}

func (o *acmeChallengeObserver) Reused(ctx context.Context, value cert.ChallengeRecord) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, existing := range o.state.Challenges {
		if existing.ChallengeURL == value.ChallengeURL {
			return &dnsgo.Error{Provider: value.Provider, Operation: "acme_challenge", Code: dnsgo.CodeConflict,
				Message: "challenge already has a tracked DNS record"}
		}
	}
	o.state.Challenges = append(o.state.Challenges, challengeRecord{ChallengeURL: value.ChallengeURL,
		Provider: value.Provider, ZoneID: value.ZoneID, RecordID: value.RecordID,
		Name: value.Name, Type: value.Type, Value: value.Value, Owned: false})
	if err := o.runner.Store.Save(ctx, "certificate", o.id, o.state); err != nil {
		o.state.Challenges = o.state.Challenges[:len(o.state.Challenges)-1]
		return err
	}
	return nil
}

func (o *acmeChallengeObserver) Removed(ctx context.Context, value cert.ChallengeRecord) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	for index, existing := range o.state.Challenges {
		if existing.ChallengeURL == value.ChallengeURL {
			o.state.Challenges = append(o.state.Challenges[:index], o.state.Challenges[index+1:]...)
			return o.runner.Store.Save(ctx, "certificate", o.id, o.state)
		}
	}
	return nil
}

type certificateState struct {
	Phase                   string
	LastAttempt             time.Time
	LastError               string
	Result                  cert.IssueResult
	PendingCertKeyPEM       []byte
	Order                   cert.CloudOrder
	Challenges              []challengeRecord
	ChallengeCreatedAt      time.Time
	Deployments             map[string]string
	DeploymentVersions      map[string]string
	DeployErrors            map[string]string
	DeploymentResults       map[string]deploy.Result
	TargetLocations         map[string]deploy.Result
	IssueVersion            string
	PendingIssueVersion     string
	PendingOperationVersion string
	ManualNoticeAt          time.Time
}

func (r *Runner) certificates(ctx context.Context, now time.Time) error {
	var failures []error
	for _, config := range r.Config.Certificates {
		if err := r.certificate(ctx, config, now); err != nil {
			failures = append(failures, fmt.Errorf("certificate %s: %w", config.ID, err))
		}
	}
	return errors.Join(failures...)
}

func (r *Runner) certificate(ctx context.Context, config CertificateConfig, now time.Time) error {
	var state certificateState
	if _, err := r.Store.Load(ctx, "certificate", config.ID, &state); err != nil {
		return err
	}
	if state.Deployments == nil {
		state.Deployments = map[string]string{}
	}
	if state.DeploymentVersions == nil {
		state.DeploymentVersions = map[string]string{}
	}
	if state.DeployErrors == nil {
		state.DeployErrors = map[string]string{}
	}
	if state.DeploymentResults == nil {
		state.DeploymentResults = map[string]deploy.Result{}
	}
	if state.TargetLocations == nil {
		state.TargetLocations = map[string]deploy.Result{}
		for id, result := range state.DeploymentResults {
			if state.Deployments[id] != "" && result.Location != "" {
				state.TargetLocations[id] = result
			}
		}
	}
	if state.Phase == "rejected" && len(state.Challenges) > 0 {
		if err := r.cleanupChallenges(ctx, config, &state); err != nil {
			return err
		}
	}
	if strings.HasPrefix(state.Phase, "unknown") || state.Phase == "issuing" || state.Phase == "rejected" || strings.HasPrefix(state.Phase, "deploying:") {
		return fmt.Errorf("previous certificate operation has uncertain outcome (%s); inspect provider state before resetting it", state.Phase)
	}
	if strings.HasPrefix(state.Phase, "pending_deploy:") {
		return r.pollCertificateDeployment(ctx, config, &state, now)
	}
	if config.RenewDays <= 0 {
		config.RenewDays = 7
	}
	if config.Authority == "manual" {
		return r.manualCertificate(ctx, config, &state, now)
	}
	requestVersion := certificateIssueVersion(config)
	if state.Phase == "pending" || state.Phase == "validating" {
		if state.PendingOperationVersion != "" && state.PendingOperationVersion != certificateOperationVersion(config) {
			return &dnsgo.Error{Provider: config.Authority, Operation: "certificate_config", Code: dnsgo.CodeConflict,
				Message: "certificate request configuration changed while an order is active"}
		}
	}
	changed := state.IssueVersion != "" && state.IssueVersion != requestVersion
	if state.IssueVersion == "" && len(state.Result.Domains) > 0 {
		changed = !sameCertificateDomains(state.Result.Domains, config.Domains)
	}
	due := changed || state.Result.NotAfter.IsZero() || !state.Result.NotAfter.After(now.Add(time.Duration(config.RenewDays)*24*time.Hour))
	if !due && state.Phase == "issued" {
		return r.deployCertificate(ctx, config, &state, now)
	}
	if !state.LastAttempt.IsZero() && now.Sub(state.LastAttempt) < time.Hour && state.Phase != "pending" && state.Phase != "validating" {
		return nil
	}
	if isACME(config.Authority) {
		return r.issueACME(ctx, config, &state, now)
	}
	return r.issueCloud(ctx, config, &state, now)
}

func (r *Runner) manualCertificate(ctx context.Context, config CertificateConfig, state *certificateState, now time.Time) error {
	info, err := os.Lstat(config.KeyFile)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 4<<20 {
		return fmt.Errorf("manual certificate private key must be a regular owner-only file below 4 MiB")
	}
	certificatePEM, err := os.ReadFile(config.CertFile)
	if err != nil {
		return err
	}
	if len(certificatePEM) > 4<<20 {
		return fmt.Errorf("manual certificate file exceeds 4 MiB")
	}
	privateKey, err := os.ReadFile(config.KeyFile)
	if err != nil {
		return err
	}
	imported, err := cert.ImportPEM(certificatePEM, privateKey)
	if err != nil {
		return err
	}
	currentHash := sha256.Sum256(state.Result.FullChainPEM)
	newHash := sha256.Sum256(imported.FullChainPEM)
	if currentHash != newHash || state.Phase != "issued" {
		state.Result = imported
		state.PendingCertKeyPEM = nil
		state.Phase, state.LastError = "issued", ""
		state.Deployments = map[string]string{}
		state.DeploymentVersions = map[string]string{}
		state.DeployErrors = map[string]string{}
		state.DeploymentResults = map[string]deploy.Result{}
		state.ManualNoticeAt = time.Time{}
		if err := r.Store.Save(ctx, "certificate", config.ID, state); err != nil {
			return err
		}
	}
	var failures []error
	if !imported.NotAfter.After(now.Add(time.Duration(config.RenewDays)*24*time.Hour)) && state.ManualNoticeAt.IsZero() {
		state.ManualNoticeAt = now
		if err := r.Store.SaveWithEvent(ctx, "certificate", config.ID, state,
			notify.Event{Kind: notify.CertOrder, Title: "手动证书即将到期：" + config.ID,
				HTML: html.EscapeString(imported.NotAfter.Format(time.RFC3339))}); err != nil {
			failures = append(failures, err)
		}
	}
	if err := r.deployCertificate(ctx, config, state, now); err != nil {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}

func isACME(authority string) bool {
	switch cert.Authority(authority) {
	case cert.LetsEncrypt, cert.ZeroSSL, cert.Google, cert.LiteSSL, cert.CustomACME:
		return true
	}
	return false
}

func normalizedCertificateDomains(domains []string) []string {
	names := make([]string, 0, len(domains))
	for _, domain := range domains {
		names = append(names, strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), ".")))
	}
	sort.Strings(names)
	return names
}

func sameCertificateDomains(left, right []string) bool {
	a, b := normalizedCertificateDomains(left), normalizedCertificateDomains(right)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func certificateIssueVersion(config CertificateConfig) string {
	algorithm := strings.ToUpper(strings.TrimSpace(config.KeyAlgorithm))
	if algorithm == "" {
		algorithm = "RSA"
	} else if algorithm == "EC" || algorithm == "ECDSA" {
		algorithm = "ECC"
	}
	size := config.KeySize
	if size == 0 {
		size = 2048
		if algorithm == "ECC" {
			size = 384
			if config.Authority == "tencent" || config.Authority == "aliyun" {
				size = 256
			}
		}
	}
	mode := config.Mode
	if mode == "" {
		mode = "live"
	}
	encoded, _ := json.Marshal(struct {
		Authority, Algorithm, Mode, Directory string
		Domains                               []string
		KeySize                               int
	}{strings.ToLower(config.Authority), algorithm, mode, strings.TrimSpace(config.Directory),
		normalizedCertificateDomains(config.Domains), size})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func certificateOperationVersion(config CertificateConfig) string {
	zones := append([]ZoneConfig(nil), config.Zones...)
	sort.Slice(zones, func(i, j int) bool {
		if zones[i].Name != zones[j].Name {
			return zones[i].Name < zones[j].Name
		}
		if zones[i].ID != zones[j].ID {
			return zones[i].ID < zones[j].ID
		}
		return zones[i].Provider < zones[j].Provider
	})
	encoded, _ := json.Marshal(struct {
		IssueVersion, Email, EABMode, EABKeyID, EABMACKey, ProxyURL string
		AcceptTerms                                                 bool
		PropagationMins                                             int
		Zones                                                       []ZoneConfig
		Aliases, Credentials                                        map[string]string
	}{IssueVersion: certificateIssueVersion(config), Email: config.Email,
		EABMode: config.EABMode, EABKeyID: config.EABKeyID, EABMACKey: config.EABMACKey, ProxyURL: config.ProxyURL,
		AcceptTerms: config.AcceptTerms, PropagationMins: config.PropagationMins,
		Zones: zones, Aliases: config.ChallengeAliases, Credentials: config.Credentials})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func (r *Runner) issueACME(ctx context.Context, config CertificateConfig, state *certificateState, now time.Time) error {
	httpClient, err := proxyHTTPClient(config.ProxyURL)
	if err != nil {
		return err
	}
	accountKey, err := cert.PrepareAccountKey(state.Result.AccountKeyPEM)
	if err != nil {
		return err
	}
	state.Result.AccountKeyPEM = accountKey
	certificateKey, err := cert.PrepareCertificateKey(state.PendingCertKeyPEM, config.KeyAlgorithm, config.KeySize)
	if err != nil {
		return err
	}
	state.PendingCertKeyPEM = certificateKey
	zones := make([]cert.ZoneBinding, 0, len(config.Zones))
	for _, z := range config.Zones {
		zones = append(zones, cert.ZoneBinding{Name: z.Name, ID: z.ID, Provider: r.DNS[z.Provider]})
	}
	issuer := cert.ACMEIssuer{Config: cert.ACMEConfig{Authority: cert.Authority(config.Authority),
		Mode: config.Mode, Directory: config.Directory, Email: config.Email, AcceptTerms: config.AcceptTerms,
		HTTPClient: httpClient,
		EABMode:    config.EABMode, EABKeyID: config.EABKeyID, EABMACKey: config.EABMACKey,
		AccountKeyPEM: state.Result.AccountKeyPEM, AccountURL: state.Result.AccountURL,
		Zones: zones, ChallengeAliases: config.ChallengeAliases,
		ChallengeObserver:  &acmeChallengeObserver{runner: r, id: config.ID, state: state},
		PropagationTimeout: time.Duration(config.PropagationMins) * time.Minute}}
	state.PendingIssueVersion = certificateIssueVersion(config)
	state.PendingOperationVersion = certificateOperationVersion(config)
	state.Phase, state.LastAttempt = "issuing", now
	if err := r.Store.Save(ctx, "certificate", config.ID, state); err != nil {
		return err
	}
	request := cert.IssueRequest{Domains: config.Domains, KeyAlgorithm: config.KeyAlgorithm,
		KeySize: config.KeySize, CertificateKeyPEM: certificateKey}
	result, err := issuer.Issue(ctx, request)
	if len(result.AccountKeyPEM) != 0 {
		state.Result.AccountKeyPEM = result.AccountKeyPEM
		state.Result.AccountURL = result.AccountURL
	}
	if err != nil {
		if len(result.PrivateKeyPEM) != 0 {
			state.PendingCertKeyPEM = result.PrivateKeyPEM
		}
		state.Phase, state.LastError = "error", SafeError(err)
		if len(state.Challenges) > 0 {
			state.Phase = "unknown_challenge"
		} else if dnsgo.IsCode(err, dnsgo.CodeResultUnknown) {
			state.Phase = "unknown_issue"
		}
		if saveErr := r.Store.SaveWithEvent(ctx, "certificate", config.ID, state,
			notify.Event{Kind: notify.CertOrder, Title: "证书签发失败：" + config.ID,
				HTML: html.EscapeString(SafeError(err))}); saveErr != nil {
			return errors.Join(err, saveErr)
		}
		return err
	}
	state.Result, state.Phase, state.LastError = result, "issued", ""
	state.IssueVersion = state.PendingIssueVersion
	state.PendingIssueVersion, state.PendingOperationVersion = "", ""
	state.PendingCertKeyPEM = nil
	state.Deployments = map[string]string{}
	state.DeploymentVersions = map[string]string{}
	state.DeployErrors = map[string]string{}
	state.DeploymentResults = map[string]deploy.Result{}
	if len(state.Challenges) > 0 {
		state.Phase = "unknown_challenge"
	}
	if err := r.Store.SaveWithEvent(ctx, "certificate", config.ID, state,
		notify.Event{Kind: notify.CertOrder, Success: true, Title: "证书签发成功：" + config.ID,
			HTML: html.EscapeString(strings.Join(result.Domains, ", "))}); err != nil {
		return err
	}
	if state.Phase == "unknown_challenge" {
		return &dnsgo.Error{Provider: config.Authority, Operation: "acme_challenge", Code: dnsgo.CodeResultUnknown,
			Message: "certificate issued but DNS challenge cleanup is unconfirmed"}
	}
	return r.deployCertificate(ctx, config, state, now)
}

func cloudIssuer(config CertificateConfig, httpClient *http.Client) (cert.CloudIssuer, error) {
	v := config.Credentials
	switch config.Authority {
	case "tencent":
		return cert.NewTencent(cert.TencentConfig{SecretID: v["secret_id"], SecretKey: v["secret_key"], Email: config.Email, Endpoint: v["endpoint"], HTTPClient: httpClient})
	case "aliyun":
		return cert.NewAliyun(cert.AliyunConfig{AccessKeyID: v["access_key_id"], AccessKeySecret: v["access_key_secret"], Endpoint: v["endpoint"], HTTPClient: httpClient})
	case "ucloud":
		return cert.NewUCloud(cert.UCloudConfig{PublicKey: v["public_key"], PrivateKey: v["private_key"],
			UserName: v["user_name"], Phone: v["phone"], Email: config.Email,
			CompanyName: v["company_name"], CompanyAddress: v["company_address"],
			CompanyRegion: v["company_region"], CompanyCity: v["company_city"],
			CompanyCountry: v["company_country"], CompanyDivision: v["company_division"],
			CompanyPostalCode: v["company_postal_code"], AdminTitle: v["admin_title"], Endpoint: v["endpoint"], HTTPClient: httpClient})
	default:
		return nil, fmt.Errorf("unknown certificate authority %q", config.Authority)
	}
}

func (r *Runner) issueCloud(ctx context.Context, config CertificateConfig, state *certificateState, now time.Time) error {
	httpClient, err := proxyHTTPClient(config.ProxyURL)
	if err != nil {
		return err
	}
	issuer, err := cloudIssuer(config, httpClient)
	if err != nil {
		return err
	}
	request := cert.IssueRequest{Domains: config.Domains, KeyAlgorithm: config.KeyAlgorithm, KeySize: config.KeySize}
	if state.Phase != "pending" && state.Phase != "validating" {
		state.PendingIssueVersion = certificateIssueVersion(config)
		state.PendingOperationVersion = certificateOperationVersion(config)
		state.Phase, state.LastAttempt = "unknown_start", now
		if err := r.Store.Save(ctx, "certificate", config.ID, state); err != nil {
			return err
		}
		order, err := issuer.Start(ctx, request)
		if err != nil {
			if order.ID != "" {
				state.Order = order
			}
			state.LastError = SafeError(err)
			_ = r.Store.Save(ctx, "certificate", config.ID, state)
			return fmt.Errorf("cloud order start outcome may be unknown: %w", err)
		}
		state.Order, state.Phase, state.LastError = order, "pending", ""
		if err := r.Store.Save(ctx, "certificate", config.ID, state); err != nil {
			return err
		}
	}
	if state.Phase == "pending" {
		challenges, err := issuer.Challenges(ctx, state.Order)
		if err != nil {
			return err
		}
		for _, challenge := range challenges {
			if err := r.ensureChallenge(ctx, config, state, challenge); err != nil {
				return err
			}
		}
		if len(challenges) > 0 {
			if state.ChallengeCreatedAt.IsZero() {
				state.ChallengeCreatedAt = now
				if err := r.Store.Save(ctx, "certificate", config.ID, state); err != nil {
					return err
				}
			}
			if now.Sub(state.ChallengeCreatedAt) < 10*time.Second {
				return nil
			}
			for _, challenge := range challenges {
				verified, err := verifyChallenge(ctx, challenge)
				if dnsgo.IsCode(err, dnsgo.CodeUnsupported) {
					return err
				}
				if err != nil || !verified {
					return nil // DNS propagation is checked again on the next tick.
				}
			}
		}
		state.Phase = "unknown_validation"
		if err := r.Store.Save(ctx, "certificate", config.ID, state); err != nil {
			return err
		}
		if err := issuer.SubmitValidation(ctx, state.Order); err != nil {
			state.LastError = SafeError(err)
			if !dnsgo.IsCode(err, dnsgo.CodeResultUnknown) {
				state.Phase = "pending"
			}
			if saveErr := r.Store.Save(ctx, "certificate", config.ID, state); saveErr != nil {
				return errors.Join(err, saveErr)
			}
			return err
		}
		state.Phase, state.LastError = "validating", ""
		if err := r.Store.Save(ctx, "certificate", config.ID, state); err != nil {
			return err
		}
	}
	status, err := issuer.Status(ctx, state.Order)
	if status == cert.CloudRejected {
		state.Phase, state.LastError, state.LastAttempt = "rejected", SafeError(err), now
		if state.LastError == "" {
			state.LastError = "cloud certificate order rejected"
		}
		if saveErr := r.Store.SaveWithEvent(ctx, "certificate", config.ID, state,
			notify.Event{Kind: notify.CertOrder, Title: "证书签发失败：" + config.ID, HTML: "云证书订单未通过验证"}); saveErr != nil {
			return errors.Join(err, saveErr)
		}
		if cleanupErr := r.cleanupChallenges(ctx, config, state); cleanupErr != nil {
			return errors.Join(err, cleanupErr)
		}
		if err != nil {
			return err
		}
		return fmt.Errorf("cloud certificate order rejected")
	}
	if err != nil {
		return err
	}
	if status == cert.CloudPending {
		return nil
	}
	if status != cert.CloudIssued {
		return &dnsgo.Error{Provider: config.Authority, Operation: "certificate_status",
			Code: dnsgo.CodeResultUnknown, Message: "unknown cloud certificate status"}
	}
	result, err := issuer.Download(ctx, state.Order)
	if err != nil {
		return err
	}
	state.Result, state.Phase, state.LastError = result, "issued", ""
	state.IssueVersion = state.PendingIssueVersion
	state.PendingIssueVersion, state.PendingOperationVersion = "", ""
	state.ChallengeCreatedAt = time.Time{}
	state.PendingCertKeyPEM = nil
	state.Deployments = map[string]string{}
	state.DeploymentVersions = map[string]string{}
	state.DeployErrors = map[string]string{}
	state.DeploymentResults = map[string]deploy.Result{}
	if err := r.Store.SaveWithEvent(ctx, "certificate", config.ID, state,
		notify.Event{Kind: notify.CertOrder, Success: true, Title: "证书签发成功：" + config.ID,
			HTML: html.EscapeString(strings.Join(config.Domains, ", "))}); err != nil {
		return err
	}
	if err := r.cleanupChallenges(ctx, config, state); err != nil {
		return err
	}
	return r.deployCertificate(ctx, config, state, now)
}

func (r *Runner) challengeZone(config CertificateConfig, name string) (ZoneConfig, string, error) {
	name = strings.Trim(strings.ToLower(name), ".")
	var best ZoneConfig
	for _, zone := range config.Zones {
		zoneName := strings.Trim(strings.ToLower(zone.Name), ".")
		if (name == zoneName || strings.HasSuffix(name, "."+zoneName)) && len(zoneName) > len(best.Name) {
			best = zone
		}
	}
	if best.Name == "" {
		return ZoneConfig{}, "", fmt.Errorf("no DNS zone binding for %s", name)
	}
	relative := "@"
	if name != strings.Trim(strings.ToLower(best.Name), ".") {
		relative = strings.TrimSuffix(name, "."+strings.Trim(strings.ToLower(best.Name), "."))
	}
	return best, relative, nil
}

func (r *Runner) ensureChallenge(ctx context.Context, config CertificateConfig, state *certificateState, challenge cert.DNSChallenge) error {
	if challenge.Name == "" || challenge.Value == "" {
		return &dnsgo.Error{Provider: "certificate", Operation: "challenge_record",
			Code: dnsgo.CodeInvalidInput, Message: "challenge name and value are required"}
	}
	if !strings.EqualFold(challenge.Type, "TXT") && !strings.EqualFold(challenge.Type, "CNAME") {
		return &dnsgo.Error{Provider: "certificate", Operation: "challenge_record",
			Code: dnsgo.CodeUnsupported, Message: "unsupported DNS challenge type"}
	}
	for _, record := range state.Challenges {
		if record.Name == challenge.Name && record.Type == challenge.Type && record.Value == challenge.Value {
			provider := r.DNS[record.Provider]
			if provider == nil {
				return fmt.Errorf("unknown challenge provider")
			}
			current, err := provider.GetRecord(ctx, record.ZoneID, record.RecordID)
			if err != nil {
				return err
			}
			if !challengeMatches(current, record.Type, record.Value) || current.Enabled != nil && !*current.Enabled {
				return &dnsgo.Error{Provider: provider.Kind(), Operation: "challenge_record", Code: dnsgo.CodeConflict,
					Message: "stored challenge record changed or is disabled; inspect DNS before continuing"}
			}
			return nil
		}
	}
	targetName := challenge.Name
	if alias := config.ChallengeAliases[strings.Trim(strings.ToLower(challenge.Name), ".")]; alias != "" {
		targetName = alias
	}
	zone, relative, err := r.challengeZone(config, targetName)
	if err != nil {
		return err
	}
	provider := r.DNS[zone.Provider]
	if provider == nil {
		return fmt.Errorf("unknown challenge provider")
	}
	listed, err := dnsgo.ListSubdomainRecords(ctx, provider, dnsgo.Zone{ID: zone.ID, Name: zone.Name}, relative,
		dnsgo.SubdomainQuery{Type: challenge.Type, PageSize: int(^uint(0) >> 1)})
	if err != nil {
		return err
	}
	for _, record := range listed.Items {
		if record.ID == "" || !challengeMatches(record, challenge.Type, challenge.Value) {
			continue
		}
		if record.Enabled != nil && !*record.Enabled {
			return &dnsgo.Error{Provider: provider.Kind(), Operation: "challenge_record", Code: dnsgo.CodeConflict,
				Message: "matching challenge record is disabled; inspect DNS before continuing"}
		}
		state.Challenges = append(state.Challenges, challengeRecord{ZoneID: zone.ID, Provider: zone.Provider,
			RecordID: record.ID, Name: challenge.Name, Type: challenge.Type, Value: challenge.Value, Owned: false})
		return r.Store.Save(ctx, "certificate", config.ID, state)
	}
	ttl := 600
	if minimum, err := provider.MinTTL(ctx, zone.ID); err == nil && minimum > ttl {
		ttl = minimum
	}
	created, err := provider.CreateRecord(ctx, zone.ID, dnsgo.Record{Name: relative, Type: challenge.Type, Value: challenge.Value, TTL: ttl})
	if err != nil {
		if dnsgo.IsCode(err, dnsgo.CodeResultUnknown) {
			if created.ID != "" {
				state.Challenges = append(state.Challenges, challengeRecord{ZoneID: zone.ID, Provider: zone.Provider,
					RecordID: created.ID, Name: challenge.Name, Type: challenge.Type, Value: challenge.Value, Owned: true})
			}
			state.Phase, state.LastError = "unknown_challenge", SafeError(err)
			if saveErr := r.Store.Save(ctx, "certificate", config.ID, state); saveErr != nil {
				return errors.Join(err, saveErr)
			}
		}
		return err
	}
	if created.ID == "" {
		state.Phase, state.LastError = "unknown_challenge", "challenge record creation returned no ID"
		if err := r.Store.Save(ctx, "certificate", config.ID, state); err != nil {
			return err
		}
		return &dnsgo.Error{Provider: provider.Kind(), Operation: "challenge_record", Code: dnsgo.CodeResultUnknown,
			Message: "challenge record creation returned no ID; inspect DNS before retry"}
	}
	state.Challenges = append(state.Challenges, challengeRecord{ZoneID: zone.ID, Provider: zone.Provider,
		RecordID: created.ID, Name: challenge.Name, Type: challenge.Type, Value: challenge.Value, Owned: true})
	return r.Store.Save(ctx, "certificate", config.ID, state)
}

func challengeMatches(record dnsgo.Record, recordType, value string) bool {
	if !strings.EqualFold(record.Type, recordType) {
		return false
	}
	if record.Value == value {
		return true
	}
	for _, candidate := range record.Values {
		if candidate == value {
			return true
		}
	}
	return false
}

func verifyChallenge(ctx context.Context, challenge cert.DNSChallenge) (bool, error) {
	switch strings.ToUpper(challenge.Type) {
	case "TXT":
		values, err := net.DefaultResolver.LookupTXT(ctx, challenge.Name)
		if err != nil {
			return false, err
		}
		for _, value := range values {
			if value == challenge.Value {
				return true, nil
			}
		}
		return false, nil
	case "CNAME":
		value, err := net.DefaultResolver.LookupCNAME(ctx, challenge.Name)
		return strings.EqualFold(strings.Trim(value, "."), strings.Trim(challenge.Value, ".")), err
	default:
		return false, &dnsgo.Error{Provider: "certificate", Operation: "verify_challenge",
			Code: dnsgo.CodeUnsupported, Message: "unsupported DNS challenge type"}
	}
}

func (r *Runner) cleanupChallenges(ctx context.Context, config CertificateConfig, state *certificateState) error {
	var kept []challengeRecord
	var failures []error
	for _, record := range state.Challenges {
		if !record.Owned {
			continue
		}
		if record.RecordID == "" {
			kept = append(kept, record)
			failures = append(failures, &dnsgo.Error{Provider: record.Provider, Operation: "challenge_cleanup",
				Code: dnsgo.CodeResultUnknown, Message: "challenge record ID is unknown; inspect DNS before cleanup"})
			continue
		}
		provider := r.DNS[record.Provider]
		if provider == nil {
			kept = append(kept, record)
			failures = append(failures, fmt.Errorf("missing DNS provider %s", record.Provider))
			continue
		}
		current, err := provider.GetRecord(ctx, record.ZoneID, record.RecordID)
		if dnsgo.IsCode(err, dnsgo.CodeNotFound) {
			continue
		}
		if err != nil {
			kept = append(kept, record)
			failures = append(failures, err)
			continue
		}
		if !challengeMatches(current, record.Type, record.Value) {
			kept = append(kept, record)
			failures = append(failures, &dnsgo.Error{Provider: provider.Kind(), Operation: "challenge_cleanup", Code: dnsgo.CodeConflict,
				Message: "challenge record changed; refusing to delete it"})
			continue
		}
		if err := provider.DeleteRecord(ctx, record.ZoneID, record.RecordID); err != nil && !dnsgo.IsCode(err, dnsgo.CodeNotFound) {
			kept = append(kept, record)
			failures = append(failures, err)
		}
	}
	state.Challenges = kept
	if err := r.Store.Save(ctx, "certificate", config.ID, state); err != nil {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}

func deploymentVersion(certificatePEM []byte, target DeploymentConfig, domains []string) string {
	certificateHash := sha256.Sum256(certificatePEM)
	names := append([]string(nil), domains...)
	sort.Strings(names)
	encoded, _ := json.Marshal(struct {
		Certificate string
		Target      string
		Endpoint    string
		ProxyURL    string
		Values      map[string]string
		Domains     []string
	}{Certificate: hex.EncodeToString(certificateHash[:]), Target: target.Target,
		Endpoint: target.Endpoint, ProxyURL: target.ProxyURL, Values: target.Values, Domains: names})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func (r *Runner) deployCertificate(ctx context.Context, config CertificateConfig, state *certificateState, now time.Time) error {
	if len(state.Challenges) != 0 {
		if err := r.cleanupChallenges(ctx, config, state); err != nil {
			return err
		}
	}
	if len(state.Result.FullChainPEM) == 0 || len(state.Result.PrivateKeyPEM) == 0 {
		return fmt.Errorf("signed certificate material is missing")
	}
	var failures []error
	for _, targetConfig := range config.Deployments {
		version := deploymentVersion(state.Result.FullChainPEM, targetConfig, state.Result.Domains)
		if state.Deployments[targetConfig.ID] == version {
			continue
		}
		values := make(map[string]string, len(targetConfig.Values)+1)
		for key, value := range targetConfig.Values {
			values[key] = value
		}
		if previous := state.TargetLocations[targetConfig.ID]; previous.Target == targetConfig.Target && previous.Location != "" {
			key := reusableTargetLocationKey(targetConfig.Target)
			if key != "" && values[key] == "" {
				values[key] = previous.Location
			}
		}
		httpClient, err := proxyHTTPClient(targetConfig.ProxyURL)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		target, err := deploy.New(targetConfig.Target, deploy.Config{Values: values, Domains: state.Result.Domains, Endpoint: targetConfig.Endpoint, HTTPClient: httpClient})
		if err != nil {
			failures = append(failures, err)
			continue
		}
		state.DeploymentVersions[targetConfig.ID] = version
		state.Phase = "deploying:" + targetConfig.ID
		if err := r.Store.Save(ctx, "certificate", config.ID, state); err != nil {
			return err
		}
		result, err := target.Deploy(ctx, deploy.Material{FullChainPEM: state.Result.FullChainPEM, PrivateKeyPEM: state.Result.PrivateKeyPEM})
		state.DeploymentResults[targetConfig.ID] = result
		if err != nil {
			state.DeployErrors[targetConfig.ID] = SafeError(err)
			if result.Written || dnsgo.IsCode(err, dnsgo.CodeResultUnknown) {
				state.Phase = "unknown_deploy:" + targetConfig.ID
			} else {
				state.Phase = "issued"
				state.LastAttempt = now
			}
			_ = r.Store.SaveWithEvent(ctx, "certificate", config.ID, state,
				notify.Event{Kind: notify.CertDeploy, Title: "证书部署失败：" + targetConfig.ID,
					HTML: html.EscapeString(SafeError(err))})
			failures = append(failures, err)
			if result.Written || dnsgo.IsCode(err, dnsgo.CodeResultUnknown) {
				break
			}
			continue
		}
		if result.Pending {
			state.Phase = "pending_deploy:" + targetConfig.ID
			if err := r.Store.Save(ctx, "certificate", config.ID, state); err != nil {
				return err
			}
			return nil
		}
		state.Phase = "issued"
		state.Deployments[targetConfig.ID] = version
		if result.Location != "" {
			state.TargetLocations[targetConfig.ID] = result
		}
		delete(state.DeployErrors, targetConfig.ID)
		if err := r.Store.SaveWithEvent(ctx, "certificate", config.ID, state,
			notify.Event{Kind: notify.CertDeploy, Success: true, Title: "证书部署成功：" + targetConfig.ID,
				HTML: html.EscapeString(strings.Join(config.Domains, ", "))}); err != nil {
			return err
		}
	}
	return errors.Join(failures...)
}

func (r *Runner) pollCertificateDeployment(ctx context.Context, config CertificateConfig, state *certificateState, now time.Time) error {
	id := strings.TrimPrefix(state.Phase, "pending_deploy:")
	var targetConfig *DeploymentConfig
	for index := range config.Deployments {
		if config.Deployments[index].ID == id {
			targetConfig = &config.Deployments[index]
			break
		}
	}
	if targetConfig == nil {
		return fmt.Errorf("pending deployment %s is absent from configuration", id)
	}
	attemptVersion := state.DeploymentVersions[id]
	if attemptVersion == "" || attemptVersion != deploymentVersion(state.Result.FullChainPEM, *targetConfig, state.Result.Domains) {
		state.Phase = "unknown_deploy:" + id
		state.DeployErrors[id] = "deployment target configuration changed while a remote task was pending"
		if err := r.Store.Save(ctx, "certificate", config.ID, state); err != nil {
			return err
		}
		return &dnsgo.Error{Provider: targetConfig.Target, Operation: "poll_deployment", Code: dnsgo.CodeConflict,
			Message: "deployment target configuration changed; inspect the pending remote task"}
	}
	result := state.DeploymentResults[id]
	if !result.Pending || result.Target != targetConfig.Target {
		return fmt.Errorf("pending deployment %s has inconsistent stored result", id)
	}
	values := make(map[string]string, len(targetConfig.Values)+1)
	for key, value := range targetConfig.Values {
		values[key] = value
	}
	if previous := state.TargetLocations[id]; previous.Target == targetConfig.Target && previous.Location != "" {
		if key := reusableTargetLocationKey(targetConfig.Target); key != "" && values[key] == "" {
			values[key] = previous.Location
		}
	}
	httpClient, err := proxyHTTPClient(targetConfig.ProxyURL)
	if err != nil {
		return err
	}
	target, err := deploy.New(targetConfig.Target, deploy.Config{Values: values, Domains: state.Result.Domains, Endpoint: targetConfig.Endpoint, HTTPClient: httpClient})
	if err != nil {
		return err
	}
	poller, ok := target.(deploy.Poller)
	if !ok {
		return fmt.Errorf("deployment target %s cannot inspect its pending task", targetConfig.Target)
	}
	updated, err := poller.Poll(ctx, result)
	state.DeploymentResults[id] = updated
	if err != nil {
		if dnsgo.IsCode(err, dnsgo.CodeConflict) {
			state.Phase = "unknown_deploy:" + id
			state.DeployErrors[id] = SafeError(err)
			if saveErr := r.Store.SaveWithEvent(ctx, "certificate", config.ID, state,
				notify.Event{Kind: notify.CertDeploy, Title: "证书部署失败：" + id,
					HTML: html.EscapeString(SafeError(err))}); saveErr != nil {
				return errors.Join(err, saveErr)
			}
		}
		if !dnsgo.IsCode(err, dnsgo.CodeConflict) {
			if saveErr := r.Store.Save(ctx, "certificate", config.ID, state); saveErr != nil {
				return errors.Join(err, saveErr)
			}
		}
		return err
	}
	if updated.Pending {
		return r.Store.Save(ctx, "certificate", config.ID, state)
	}
	state.Deployments[id] = attemptVersion
	if updated.Location != "" {
		state.TargetLocations[id] = updated
	}
	state.Phase = "issued"
	delete(state.DeployErrors, id)
	if err := r.Store.SaveWithEvent(ctx, "certificate", config.ID, state,
		notify.Event{Kind: notify.CertDeploy, Success: true, Title: "证书部署成功：" + id,
			HTML: html.EscapeString(strings.Join(config.Domains, ", "))}); err != nil {
		return err
	}
	return r.deployCertificate(ctx, config, state, now)
}

func reusableTargetLocationKey(target string) string {
	switch target {
	case "axisnow":
		return "uuid"
	case "rainyun", "lecdn", "cdnfly", "nginxproxymanager":
		return "id"
	case "aws":
		return "cert_id"
	default:
		return ""
	}
}
