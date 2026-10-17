package deploy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

type GoEdge struct {
	endpoint    string
	accessKeyID string
	accessKey   string
	userType    string
	systemType  string
	domains     []string
	client      *http.Client
}

func init() {
	register("goedge", func(config Config) (Target, error) {
		if config.Endpoint == "" {
			config.Endpoint = config.Values["url"]
		}
		endpoint, err := targetEndpoint(config, "")
		if err != nil {
			return nil, err
		}
		id, key := strings.TrimSpace(config.Values["accessKeyId"]), strings.TrimSpace(config.Values["accessKey"])
		domains := splitList(config.Values["domainList"])
		if id == "" || key == "" || len(domains) == 0 {
			return nil, errors.New("GoEdge access keys and deployment domains are required")
		}
		return &GoEdge{endpoint: endpoint, accessKeyID: id, accessKey: key, userType: config.Values["usertype"],
			systemType: config.Values["systype"], domains: domains, client: client(config)}, nil
	})
}

func (t *GoEdge) Kind() string { return "goedge" }

func (t *GoEdge) Check(ctx context.Context) error { _, err := t.token(ctx); return err }

func (t *GoEdge) Deploy(ctx context.Context, material Material) (Result, error) {
	leaf, err := certificate(material)
	if err != nil {
		return Result{}, err
	}
	token, err := t.token(ctx)
	if err != nil {
		return Result{}, err
	}
	data, err := t.call(ctx, "/SSLCertService/listSSLCerts", map[string]any{"domains": t.domains, "offset": 0, "size": 10}, token)
	if err != nil {
		return Result{}, err
	}
	var listResponse struct {
		SSLCertsJSON string `json:"sslCertsJSON"`
	}
	if err := json.Unmarshal(data, &listResponse); err != nil {
		return Result{}, errors.New("invalid GoEdge certificate list response")
	}
	decoded, err := base64.StdEncoding.DecodeString(listResponse.SSLCertsJSON)
	if err != nil {
		return Result{}, errors.New("invalid GoEdge encoded certificate list")
	}
	var list []struct {
		ID          json.RawMessage `json:"id"`
		Name        string          `json:"name"`
		Description string          `json:"description"`
		ServerName  string          `json:"serverName"`
	}
	if err := json.Unmarshal(decoded, &list); err != nil {
		return Result{}, errors.New("invalid GoEdge certificate list")
	}
	name := fmt.Sprintf("%s-%d", strings.TrimPrefix(leaf.Subject.CommonName, "*."), leaf.NotBefore.Unix())
	base := map[string]any{"isOn": true, "isCA": false, "certData": base64.StdEncoding.EncodeToString(material.FullChainPEM),
		"keyData": base64.StdEncoding.EncodeToString(material.PrivateKeyPEM), "timeBeginAt": leaf.NotBefore.Unix(), "timeEndAt": leaf.NotAfter.Unix(),
		"dnsNames": t.domains, "commonNames": []string{leaf.Issuer.CommonName}}
	result := Result{Target: t.Kind()}
	if len(list) == 0 {
		base["name"], base["description"], base["serverName"] = name, name, leaf.Subject.CommonName
		created, err := t.call(ctx, "/SSLCertService/createSSLCert", base, token)
		if err != nil {
			return Result{Target: t.Kind(), Written: true}, err
		}
		var createdInfo struct {
			ID json.RawMessage `json:"sslCertId"`
		}
		_ = json.Unmarshal(created, &createdInfo)
		result.Location = scalarID(createdInfo.ID)
		result.Written = true
		if result.Location == "" {
			return result, errors.New("GoEdge created certificate but did not return ID")
		}
		return result, nil
	}
	for _, item := range list {
		params := make(map[string]any, len(base)+4)
		for key, value := range base {
			params[key] = value
		}
		params["sslCertId"], params["name"], params["description"], params["serverName"] = item.ID, item.Name, item.Description, item.ServerName
		if _, err := t.call(ctx, "/SSLCertService/updateSSLCert", params, token); err != nil {
			result.Written = true
			return result, err
		}
		result.Written = true
		if result.Location != "" {
			result.Location += ","
		}
		result.Location += scalarID(item.ID)
	}
	return result, nil
}

func (t *GoEdge) token(ctx context.Context) (string, error) {
	data, err := t.call(ctx, "/APIAccessTokenService/getAPIAccessToken", map[string]string{
		"type": t.userType, "accessKeyId": t.accessKeyID, "accessKey": t.accessKey,
	}, "")
	if err != nil {
		return "", err
	}
	var value struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(data, &value); err != nil || value.Token == "" {
		return "", errors.New("GoEdge token response is invalid")
	}
	return value.Token, nil
}

func (t *GoEdge) call(ctx context.Context, path string, payload any, token string) (json.RawMessage, error) {
	headers := map[string]string{}
	if token != "" {
		if t.systemType == "1" {
			headers["X-Cloud-Access-Token"] = token
		} else {
			headers["X-Edge-Access-Token"] = token
		}
	}
	status, content, err := requestJSON(ctx, t.client, http.MethodPost, t.endpoint+path, headers, payload)
	if err != nil {
		return nil, err
	}
	var response struct {
		Code int             `json:"code"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(content, &response); err != nil {
		return nil, errors.New("invalid GoEdge API response")
	}
	if status < 200 || status >= 300 || response.Code != 200 {
		return nil, fmt.Errorf("GoEdge API rejected request (HTTP %d, code %d)", status, response.Code)
	}
	return response.Data, nil
}

var _ Target = (*GoEdge)(nil)
