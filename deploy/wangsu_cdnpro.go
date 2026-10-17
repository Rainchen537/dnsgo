package deploy

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

func (t *Wangsu) encryptedCDNProKey(privateKey []byte, date string) (string, error) {
	signKey := t.apiKey
	if t.spKey != "" {
		signKey = t.spKey
	}
	mac := hmac.New(sha256.New, []byte(signKey))
	_, _ = mac.Write([]byte(date))
	derived := mac.Sum(nil)
	if len(derived) != 32 {
		return "", errors.New("Wangsu CDNPro key derivation failed")
	}
	block, err := aes.NewCipher(derived[16:32])
	if err != nil {
		return "", errors.New("Wangsu CDNPro AES initialization failed")
	}
	padding := aes.BlockSize - len(privateKey)%aes.BlockSize
	plain := append(append([]byte(nil), privateKey...), bytesRepeat(byte(padding), padding)...)
	encrypted := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, derived[:16]).CryptBlocks(encrypted, plain)
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

func bytesRepeat(value byte, count int) []byte {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return result
}

func (t *Wangsu) cdnProCertID(ctx context.Context, material Material, name string) (string, bool, error) {
	response, err := t.call(ctx, http.MethodGet, "/cdn/certificates?search="+url.QueryEscape(name), nil, nil, "", nil)
	if err != nil {
		return "", false, err
	}
	var listing struct {
		Count        int `json:"count"`
		Certificates []struct {
			Name string          `json:"name"`
			ID   json.RawMessage `json:"certificateId"`
		} `json:"certificates"`
	}
	if json.Unmarshal(response.body, &listing) != nil {
		return "", false, errors.New("invalid Wangsu CDNPro certificate list")
	}
	for _, item := range listing.Certificates {
		if item.Name == name && scalarID(item.ID) != "" {
			return scalarID(item.ID), false, nil
		}
	}
	date := time.Now().UTC().Format(http.TimeFormat)
	encrypted, err := t.encryptedCDNProKey(material.PrivateKeyPEM, date)
	if err != nil {
		return "", false, err
	}
	created, err := t.call(ctx, http.MethodPost, "/cdn/certificates", map[string]any{
		"name": name, "autoRenew": "Off", "newVersion": map[string]string{
			"privateKey": encrypted, "certificate": string(material.FullChainPEM),
		},
	}, nil, date, nil)
	if err != nil {
		return "", false, err
	}
	id := wangsuLocationID(created.location)
	if id == "" {
		return "", true, errors.New("Wangsu CDNPro uploaded certificate but returned no ID")
	}
	if err := waitContext(ctx, 500*time.Millisecond); err != nil {
		return id, true, err
	}
	return id, true, nil
}

func (t *Wangsu) deployCDNPro(ctx context.Context, material Material, name string) (Result, error) {
	id, uploaded, err := t.cdnProCertID(ctx, material, name)
	result := Result{Target: t.Kind(), Location: id, Written: uploaded}
	if err != nil {
		return result, err
	}
	hostname, err := t.call(ctx, http.MethodGet, "/cdn/hostnames/"+url.PathEscape(t.domain), nil, nil, "", nil)
	if err != nil {
		return result, err
	}
	var info struct {
		PropertyInProduction struct {
			PropertyID    json.RawMessage `json:"propertyId"`
			Version       json.RawMessage `json:"version"`
			CertificateID json.RawMessage `json:"certificateId"`
		} `json:"propertyInProduction"`
	}
	if json.Unmarshal(hostname.body, &info) != nil {
		return result, errors.New("invalid Wangsu CDNPro hostname response")
	}
	propertyID, version := scalarID(info.PropertyInProduction.PropertyID), scalarID(info.PropertyInProduction.Version)
	if propertyID == "" || version == "" {
		return result, errors.New("Wangsu CDNPro hostname has no production property")
	}
	if scalarID(info.PropertyInProduction.CertificateID) == id {
		return result, nil
	}
	property, err := t.call(ctx, http.MethodGet, "/cdn/properties/"+url.PathEscape(propertyID)+"/versions/"+url.PathEscape(version), nil, nil, "", nil)
	if err != nil {
		return result, err
	}
	var current struct {
		Configs map[string]any `json:"configs"`
	}
	if json.Unmarshal(property.body, &current) != nil || current.Configs == nil {
		return result, errors.New("invalid Wangsu CDNPro property configuration")
	}
	current.Configs["tlsCertificateId"] = id
	created, err := t.call(ctx, http.MethodPost, "/cdn/properties/"+url.PathEscape(propertyID)+"/versions", current.Configs, nil, "", nil)
	if err != nil {
		return result, err
	}
	result.Written = true
	newVersion := wangsuLocationID(created.location)
	parsedVersion, err := strconv.Atoi(newVersion)
	if err != nil || parsedVersion <= 0 {
		return result, errors.New("Wangsu CDNPro new property version is missing")
	}
	validation, err := t.call(ctx, http.MethodPost, "/cdn/validations", map[string]any{"propertyId": propertyID, "version": parsedVersion}, nil, "", nil)
	if err != nil {
		return result, err
	}
	taskID := wangsuLocationID(validation.location)
	if taskID == "" {
		return result, errors.New("Wangsu CDNPro validation task ID is missing")
	}
	validated := false
	for attempt := 0; attempt < 12; attempt++ {
		if err := waitContext(ctx, 5*time.Second); err != nil {
			return result, err
		}
		response, err := t.call(ctx, http.MethodGet, "/cdn/validations/"+url.PathEscape(taskID), nil, nil, "", nil)
		if err != nil {
			return result, err
		}
		var status struct {
			Status string `json:"status"`
		}
		if json.Unmarshal(response.body, &status) != nil {
			return result, errors.New("invalid Wangsu CDNPro validation status")
		}
		if status.Status == "failed" {
			return result, errors.New("Wangsu CDNPro property validation failed")
		}
		if status.Status == "succeeded" {
			validated = true
			break
		}
	}
	if !validated {
		return result, errors.New("Wangsu CDNPro property validation timed out")
	}
	_, err = t.call(ctx, http.MethodPost, "/cdn/deploymentTasks", map[string]any{
		"target": "production", "actions": []map[string]any{
			{"action": "deploy_cert", "certificateId": id, "version": 1},
			{"action": "deploy_property", "propertyId": propertyID, "version": parsedVersion},
		}, "name": "Deploy certificate and property for " + propertyID,
	}, nil, "", map[string]string{"Check-Certificate": "no", "Check-Usage": "no"})
	if err != nil {
		return result, err
	}
	result.Written = true
	return result, nil
}

func (t *Wangsu) deployCDNProCertificate(ctx context.Context, material Material, name string) (Result, error) {
	path := "/cdn/certificates/" + url.PathEscape(t.certID)
	response, err := t.call(ctx, http.MethodGet, path, nil, nil, "", nil)
	if err != nil {
		return Result{}, err
	}
	var current struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(response.body, &current) != nil {
		return Result{}, errors.New("invalid Wangsu CDNPro certificate details")
	}
	result := Result{Target: t.Kind(), Location: t.certID}
	if current.Name == name {
		return result, nil
	}
	date := time.Now().UTC().Format(http.TimeFormat)
	encrypted, err := t.encryptedCDNProKey(material.PrivateKeyPEM, date)
	if err != nil {
		return result, err
	}
	updated, err := t.call(ctx, http.MethodPatch, path, map[string]any{
		"name": name, "newVersion": map[string]string{
			"privateKey": encrypted, "certificate": string(material.FullChainPEM), "comments": name,
		},
	}, nil, date, nil)
	if err != nil {
		return result, err
	}
	result.Written = true
	version, parseErr := strconv.Atoi(wangsuLocationID(updated.location))
	if parseErr != nil || version <= 0 {
		version = 1
	}
	_, err = t.call(ctx, http.MethodPost, "/cdn/deploymentTasks", map[string]any{
		"target": "production", "actions": []map[string]any{{"action": "deploy_cert", "certificateId": t.certID, "version": version}},
		"name": "Deploy certificate " + name,
	}, nil, "", map[string]string{"Check-Certificate": "no", "Check-Usage": "no"})
	if err != nil {
		return result, fmt.Errorf("Wangsu CDNPro deployment task failed: %w", err)
	}
	return result, nil
}
