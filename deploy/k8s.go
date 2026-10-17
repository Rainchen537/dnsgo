package deploy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

type K8s struct {
	server     string
	token      string
	namespace  string
	secretName string
	ingresses  []string
	client     *http.Client
}

type kubeConfig struct {
	CurrentContext string `yaml:"current-context"`
	Contexts       []struct {
		Name    string `yaml:"name"`
		Context struct {
			Cluster string `yaml:"cluster"`
			User    string `yaml:"user"`
		} `yaml:"context"`
	} `yaml:"contexts"`
	Clusters []struct {
		Name    string `yaml:"name"`
		Cluster struct {
			Server   string `yaml:"server"`
			CAData   string `yaml:"certificate-authority-data"`
			CAFile   string `yaml:"certificate-authority"`
			Insecure bool   `yaml:"insecure-skip-tls-verify"`
		} `yaml:"cluster"`
	} `yaml:"clusters"`
	Users []struct {
		Name string `yaml:"name"`
		User struct {
			Token          string `yaml:"token"`
			ClientCertData string `yaml:"client-certificate-data"`
			ClientKeyData  string `yaml:"client-key-data"`
			ClientCertFile string `yaml:"client-certificate"`
			ClientKeyFile  string `yaml:"client-key"`
			AuthProvider   struct {
				Config struct {
					AccessToken string `yaml:"access-token"`
				} `yaml:"config"`
			} `yaml:"auth-provider"`
		} `yaml:"user"`
	} `yaml:"users"`
}

var k8sNamePattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`)

func init() {
	register("k8s", func(config Config) (Target, error) {
		content := config.Values["kubeconfig"]
		if content == "" {
			return nil, errors.New("Kubernetes kubeconfig is required")
		}
		var parsed kubeConfig
		if err := yaml.Unmarshal([]byte(content), &parsed); err != nil {
			return nil, errors.New("invalid Kubernetes kubeconfig")
		}
		if parsed.CurrentContext == "" {
			return nil, errors.New("kubeconfig current-context is missing")
		}
		var clusterName, userName string
		for _, item := range parsed.Contexts {
			if item.Name == parsed.CurrentContext {
				clusterName, userName = item.Context.Cluster, item.Context.User
				break
			}
		}
		if clusterName == "" || userName == "" {
			return nil, errors.New("kubeconfig current context is incomplete")
		}
		var server, caData, caFile string
		var insecure bool
		for _, item := range parsed.Clusters {
			if item.Name == clusterName {
				server, caData, caFile, insecure = item.Cluster.Server, item.Cluster.CAData, item.Cluster.CAFile, item.Cluster.Insecure
				break
			}
		}
		var token, certData, keyData, certFile, keyFile string
		for _, item := range parsed.Users {
			if item.Name == userName {
				token, certData, keyData, certFile, keyFile = item.User.Token, item.User.ClientCertData, item.User.ClientKeyData,
					item.User.ClientCertFile, item.User.ClientKeyFile
				if token == "" {
					token = item.User.AuthProvider.Config.AccessToken
				}
				break
			}
		}
		server = strings.TrimRight(server, "/")
		parsedURL, err := url.Parse(server)
		if err != nil || parsedURL.Host == "" || (parsedURL.Scheme != "https" && parsedURL.Scheme != "http") {
			return nil, errors.New("kubeconfig server URL is invalid")
		}
		if token == "" && (certData == "" || keyData == "") && (certFile == "" || keyFile == "") {
			return nil, errors.New("kubeconfig user has no token or client certificate")
		}
		namespace, secretName := strings.TrimSpace(config.Values["namespace"]), strings.TrimSpace(config.Values["secret_name"])
		if !validK8sName(namespace) || !validK8sName(secretName) {
			return nil, errors.New("Kubernetes namespace and Secret name are required")
		}
		ingresses := splitList(config.Values["ingresses"])
		for _, name := range ingresses {
			if !validK8sName(name) {
				return nil, errors.New("invalid Kubernetes Ingress name")
			}
		}
		httpClient, err := kubeHTTPClient(config, caData, caFile, certData, keyData, certFile, keyFile, insecure)
		if err != nil {
			return nil, err
		}
		return &K8s{server: server, token: token, namespace: namespace, secretName: secretName, ingresses: ingresses, client: httpClient}, nil
	})
}

func validK8sName(name string) bool {
	return len(name) > 0 && len(name) <= 253 && k8sNamePattern.MatchString(name) && !strings.Contains(name, "..")
}

func kubeHTTPClient(config Config, caData, caFile, certData, keyData, certFile, keyFile string, insecure bool) (*http.Client, error) {
	httpClient := client(config)
	copyClient := *httpClient
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if previous, ok := httpClient.Transport.(*http.Transport); ok {
		transport = previous.Clone()
	} else if httpClient.Transport != nil {
		return nil, errors.New("Kubernetes custom HTTP transport must be an http.Transport")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: insecure}
	if transport.TLSClientConfig != nil {
		tlsConfig = transport.TLSClientConfig.Clone()
		tlsConfig.InsecureSkipVerify = insecure
	}
	if caData != "" || caFile != "" {
		var caBytes []byte
		var err error
		if caData != "" {
			caBytes, err = base64.StdEncoding.DecodeString(caData)
		} else {
			caBytes, err = os.ReadFile(caFile)
		}
		if err != nil {
			return nil, errors.New("read Kubernetes CA certificate failed")
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(caBytes) {
			return nil, errors.New("invalid Kubernetes CA certificate")
		}
		tlsConfig.RootCAs = pool
	}
	if certData != "" || certFile != "" {
		var certBytes, keyBytes []byte
		var err error
		if certData != "" && keyData != "" {
			certBytes, err = base64.StdEncoding.DecodeString(certData)
			if err == nil {
				keyBytes, err = base64.StdEncoding.DecodeString(keyData)
			}
		} else if certFile != "" && keyFile != "" {
			certBytes, err = os.ReadFile(certFile)
			if err == nil {
				keyBytes, err = os.ReadFile(keyFile)
			}
		} else {
			return nil, errors.New("Kubernetes client certificate and key must be paired")
		}
		if err != nil {
			return nil, errors.New("read Kubernetes client certificate failed")
		}
		pair, err := tls.X509KeyPair(certBytes, keyBytes)
		if err != nil {
			return nil, errors.New("invalid Kubernetes client certificate")
		}
		tlsConfig.Certificates = []tls.Certificate{pair}
	}
	transport.TLSClientConfig = tlsConfig
	copyClient.Transport = transport
	copyClient.Timeout = 30 * time.Second
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &copyClient, nil
}

func (t *K8s) Kind() string { return "k8s" }

func (t *K8s) Check(ctx context.Context) error {
	status, _, err := t.call(ctx, http.MethodGet, "/version", nil, "")
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("Kubernetes version check returned HTTP %d", status)
	}
	return nil
}

func (t *K8s) Deploy(ctx context.Context, material Material) (Result, error) {
	if _, err := certificate(material); err != nil {
		return Result{}, err
	}
	path := "/api/v1/namespaces/" + t.namespace + "/secrets"
	secretPath := path + "/" + t.secretName
	status, _, err := t.call(ctx, http.MethodGet, secretPath, nil, "")
	if err != nil {
		return Result{}, err
	}
	data := map[string]string{"tls.crt": base64.StdEncoding.EncodeToString(material.FullChainPEM), "tls.key": base64.StdEncoding.EncodeToString(material.PrivateKeyPEM)}
	if status == http.StatusNotFound {
		payload := map[string]any{"apiVersion": "v1", "kind": "Secret", "metadata": map[string]string{"name": t.secretName, "namespace": t.namespace},
			"type": "kubernetes.io/tls", "data": data}
		status, _, err = t.call(ctx, http.MethodPost, path, payload, "application/json")
	} else if status >= 200 && status < 300 {
		status, _, err = t.call(ctx, http.MethodPatch, secretPath, map[string]any{"data": data, "type": "kubernetes.io/tls"}, "application/merge-patch+json")
	} else {
		return Result{}, fmt.Errorf("Kubernetes Secret lookup returned HTTP %d", status)
	}
	if err != nil {
		return Result{}, err
	}
	if status < 200 || status >= 300 {
		return Result{}, fmt.Errorf("Kubernetes Secret write returned HTTP %d", status)
	}
	result := Result{Target: t.Kind(), Location: t.namespace + "/" + t.secretName, Written: true}
	for _, ingress := range t.ingresses {
		if err := t.bindIngress(ctx, ingress); err != nil {
			return result, err
		}
	}
	return result, nil
}

func (t *K8s) bindIngress(ctx context.Context, ingress string) error {
	path := "/apis/networking.k8s.io/v1/namespaces/" + t.namespace + "/ingresses/" + ingress
	status, content, err := t.call(ctx, http.MethodGet, path, nil, "")
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("Kubernetes Ingress lookup returned HTTP %d", status)
	}
	var current struct {
		Spec struct {
			Rules []struct {
				Host string `json:"host"`
			} `json:"rules"`
			TLS []struct {
				SecretName string   `json:"secretName"`
				Hosts      []string `json:"hosts"`
			} `json:"tls"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(content, &current); err != nil {
		return errors.New("invalid Kubernetes Ingress response")
	}
	hosts := map[string]bool{}
	for _, rule := range current.Spec.Rules {
		if rule.Host != "" {
			hosts[rule.Host] = true
		}
	}
	found := false
	for i := range current.Spec.TLS {
		if current.Spec.TLS[i].SecretName != t.secretName {
			continue
		}
		found = true
		for _, host := range current.Spec.TLS[i].Hosts {
			hosts[host] = true
		}
		current.Spec.TLS[i].Hosts = sortedHostNames(hosts)
	}
	if !found {
		current.Spec.TLS = append(current.Spec.TLS, struct {
			SecretName string   `json:"secretName"`
			Hosts      []string `json:"hosts"`
		}{
			SecretName: t.secretName, Hosts: sortedHostNames(hosts),
		})
	}
	status, _, err = t.call(ctx, http.MethodPatch, path, map[string]any{"spec": map[string]any{"tls": current.Spec.TLS}}, "application/merge-patch+json")
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("Kubernetes Ingress update returned HTTP %d", status)
	}
	return nil
}

func sortedHostNames(hosts map[string]bool) []string {
	result := make([]string, 0, len(hosts))
	for host := range hosts {
		if host != "" {
			result = append(result, host)
		}
	}
	sort.Strings(result)
	return result
}

func (t *K8s) call(ctx context.Context, method, path string, payload any, contentType string) (int, []byte, error) {
	headers := map[string]string{"Accept": "application/json"}
	if t.token != "" {
		headers["Authorization"] = "Bearer " + t.token
	}
	if payload == nil {
		return request(ctx, t.client, method, t.server+path, headers, nil)
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, errors.New("encode Kubernetes request failed")
	}
	headers["Content-Type"] = contentType
	return request(ctx, t.client, method, t.server+path, headers, encoded)
}

var _ Target = (*K8s)(nil)
