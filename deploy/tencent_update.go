package deploy

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rainchen537/dnsgo"
)

var errTencentSyncTimeout = errors.New("Tencent resource sync task timed out")

type tencentBoundResource struct {
	ResourceType string `json:"ResourceType"`
	Regions      []struct {
		TotalCount int    `json:"TotalCount"`
		Region     string `json:"Region"`
	} `json:"BindResourceRegionResult"`
}

func (t *Tencent) boundResources(ctx context.Context, oldID string, attempts int) ([]tencentBoundResource, string, error) {
	client := t.ssl("")
	var created struct {
		CertTaskIDs []struct {
			TaskID json.RawMessage `json:"TaskId"`
		} `json:"CertTaskIds"`
	}
	if err := client.Call(ctx, "CreateCertificateBindResourceSyncTask", map[string]any{"CertificateIds": []string{oldID}, "IsCache": 1}, &created); err != nil {
		return nil, "", err
	}
	if len(created.CertTaskIDs) == 0 {
		return nil, "", errors.New("Tencent resource sync task returned no ID")
	}
	taskID := scalarID(created.CertTaskIDs[0].TaskID)
	if taskID == "" {
		return nil, "", errors.New("Tencent resource sync task ID is invalid")
	}
	for attempt := 0; attempt < attempts; attempt++ {
		if err := waitContext(ctx, 2*time.Second); err != nil {
			return nil, taskID, err
		}
		var status struct {
			Results []struct {
				Status             int                    `json:"Status"`
				BindResourceResult []tencentBoundResource `json:"BindResourceResult"`
			} `json:"SyncTaskBindResourceResult"`
		}
		if err := client.Call(ctx, "DescribeCertificateBindResourceTaskResult", map[string]any{"TaskIds": []string{taskID}}, &status); err != nil {
			return nil, taskID, err
		}
		if len(status.Results) == 0 {
			return nil, taskID, errors.New("Tencent resource sync task returned no results")
		}
		switch status.Results[0].Status {
		case 1:
			return status.Results[0].BindResourceResult, taskID, nil
		case 2:
			return nil, taskID, errors.New("Tencent resource sync task failed")
		}
	}
	return nil, taskID, errTencentSyncTimeout
}

func tencentResourceTypes(resources []tencentBoundResource, clbOnly bool) ([]string, []map[string]any) {
	regionTypes := map[string]bool{"clb": true, "tke": true, "apigateway": true, "waf": true, "tcb": true, "tse": true,
		"cos": true, "mqtt": true, "scf": true, "tdmq": true}
	var types []string
	var typeRegions []map[string]any
	for _, resource := range resources {
		if clbOnly && resource.ResourceType != "clb" {
			continue
		}
		total := 0
		var regions []string
		for _, region := range resource.Regions {
			if region.TotalCount <= 0 {
				continue
			}
			total += region.TotalCount
			if region.Region != "" {
				regions = append(regions, region.Region)
			}
		}
		if total == 0 {
			continue
		}
		types = append(types, resource.ResourceType)
		if len(regions) > 0 && (clbOnly || regionTypes[resource.ResourceType]) {
			typeRegions = append(typeRegions, map[string]any{"ResourceType": resource.ResourceType, "Regions": regions})
		}
	}
	return types, typeRegions
}

func (t *Tencent) updateCertificate(ctx context.Context, material Material) (Result, error) {
	oldID := strings.TrimSpace(t.values["cert_id"])
	if oldID == "" {
		return Result{}, errors.New("Tencent old certificate ID is required")
	}
	resources, taskID, err := t.boundResources(ctx, oldID, 30)
	result := Result{Target: t.Kind(), Location: oldID, Metadata: map[string]string{"sync_task_id": taskID}}
	if err != nil {
		result.Written = taskID != ""
		return result, err
	}
	types, regions := tencentResourceTypes(resources, true)
	if len(types) == 0 {
		result.Written = true // a resource-sync task was created; inspect before starting another
		return result, errors.New("Tencent certificate update has no bound CLB resources")
	}
	payload := map[string]any{"OldCertificateId": oldID, "CertificatePublicKey": string(material.FullChainPEM),
		"CertificatePrivateKey": string(material.PrivateKeyPEM), "ResourceTypes": types, "ResourceTypesRegions": regions}
	for attempt := 0; attempt < 10; attempt++ {
		var response struct {
			DeployRecordID json.RawMessage `json:"DeployRecordId"`
		}
		result.Written = true
		if err := t.ssl("").Call(ctx, "UploadUpdateCertificateInstance", payload, &response); err != nil {
			return result, err
		}
		if recordID := scalarID(response.DeployRecordID); recordID != "" && recordID != "0" {
			result.Pending = true
			result.Metadata["deploy_record_id"] = recordID
			result.Metadata["mode"] = "update"
			result.Metadata["product"] = t.product
			return result, nil
		}
		if err := waitContext(ctx, time.Second); err != nil {
			return result, err
		}
	}
	return result, &dnsgo.Error{Provider: t.Kind(), Operation: "update_certificate", Code: dnsgo.CodeResultUnknown,
		Message: "Tencent certificate update did not return a deployment task ID"}
}

func (t *Tencent) updateCertificateNew(ctx context.Context, material Material) (Result, error) {
	oldID := strings.TrimSpace(t.values["cert_id"])
	if oldID == "" {
		return Result{}, errors.New("Tencent old certificate ID is required")
	}
	resources, taskID, err := t.boundResources(ctx, oldID, 60)
	if err != nil {
		return Result{Target: t.Kind(), Location: oldID, Written: taskID != "",
			Metadata: map[string]string{"sync_task_id": taskID}}, err
	}
	result := Result{Target: t.Kind(), Location: oldID, Metadata: map[string]string{"sync_task_id": taskID}}
	types, regions := tencentResourceTypes(resources, false)
	if len(types) == 0 {
		id, uploaded, err := t.uploadCertificate(ctx, material, true)
		result.Written = uploaded
		if id != "" {
			result.Location = id
		}
		if err != nil {
			return result, err
		}
		if err := t.deleteOldCertificate(ctx, oldID, id); err != nil {
			return result, err
		}
		return result, nil
	}
	payload := map[string]any{"OldCertificateId": oldID, "CertificatePublicKey": string(material.FullChainPEM),
		"CertificatePrivateKey": string(material.PrivateKeyPEM), "ResourceTypes": types}
	if len(regions) > 0 {
		payload["ResourceTypesRegions"] = regions
	}
	var deployRecordID string
	for attempt := 0; attempt < 10; attempt++ {
		var response struct {
			DeployRecordID json.RawMessage `json:"DeployRecordId"`
		}
		result.Written = true
		if err := t.ssl("").Call(ctx, "UpdateCertificateInstance", payload, &response); err != nil {
			return result, err
		}
		deployRecordID = scalarID(response.DeployRecordID)
		if deployRecordID != "" && deployRecordID != "0" {
			break
		}
		if err := waitContext(ctx, 2*time.Second); err != nil {
			return result, err
		}
	}
	if deployRecordID == "" || deployRecordID == "0" {
		return result, &dnsgo.Error{Provider: t.Kind(), Operation: "update_certificate_new", Code: dnsgo.CodeResultUnknown,
			Message: "Tencent certificate update returned no deployment task ID"}
	}
	result.Metadata["deploy_record_id"] = deployRecordID
	leaf, _ := certificate(material)
	fingerprint := sha256.Sum256(leaf.Raw)
	result.Location = ""
	result.Pending = true
	result.Metadata["mode"] = "update_new"
	result.Metadata["product"] = t.product
	result.Metadata["old_cert_id"] = oldID
	result.Metadata["cert_cn"] = leaf.Subject.CommonName
	result.Metadata["cert_sha256"] = hex.EncodeToString(fingerprint[:])
	if t.values["delete_old_cert"] == "true" || t.values["delete_old_cert"] == "1" {
		result.Metadata["delete_old_cert"] = "true"
	}
	return result, nil
}

func (t *Tencent) findNewCertificateID(ctx context.Context, cn, fingerprint string) (string, error) {
	if cn == "" || fingerprint == "" {
		return "", errors.New("Tencent replacement certificate fingerprint is missing")
	}
	for offset := 0; offset < 10000; offset += 100 {
		var response struct {
			TotalCount   int `json:"TotalCount"`
			Certificates []struct {
				CertificateID string `json:"CertificateId"`
				Domain        string `json:"Domain"`
				Status        int    `json:"Status"`
			} `json:"Certificates"`
		}
		if err := t.ssl("").Call(ctx, "DescribeCertificates", map[string]any{
			"SearchKey": strings.TrimPrefix(cn, "*."), "Limit": 100, "Offset": offset,
		}, &response); err != nil {
			return "", err
		}
		for _, item := range response.Certificates {
			if item.Status != 1 || item.CertificateID == "" || item.Domain != cn && item.Domain != strings.TrimPrefix(cn, "*.") {
				continue
			}
			var detail struct {
				CertificatePublicKey string `json:"CertificatePublicKey"`
			}
			if err := t.ssl("").Call(ctx, "DescribeCertificateDetail", map[string]string{"CertificateId": item.CertificateID}, &detail); err != nil {
				return "", fmt.Errorf("verify Tencent replacement certificate %s: %w", item.CertificateID, err)
			}
			block, _ := pem.Decode([]byte(detail.CertificatePublicKey))
			if block == nil || block.Type != "CERTIFICATE" {
				continue
			}
			candidate, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				digest := sha256.Sum256(candidate.Raw)
				if hex.EncodeToString(digest[:]) != fingerprint {
					continue
				}
				return item.CertificateID, nil
			}
		}
		if len(response.Certificates) < 100 || response.TotalCount > 0 && offset+100 >= response.TotalCount {
			return "", errors.New("Tencent replacement certificate ID could not be verified by certificate fingerprint")
		}
	}
	return "", errors.New("Tencent replacement certificate search exceeded 100 pages")
}

func (t *Tencent) deleteOldCertificate(ctx context.Context, oldID, newID string) error {
	if (t.values["delete_old_cert"] != "true" && t.values["delete_old_cert"] != "1") || oldID == newID {
		return nil
	}
	return t.deleteOldCertificateID(ctx, oldID, newID)
}

func (t *Tencent) deleteOldCertificateID(ctx context.Context, oldID, newID string) error {
	if newID == "" {
		return errors.New("Tencent new certificate ID is missing; old certificate was retained")
	}
	if oldID == "" || oldID == newID {
		return nil
	}
	var response struct {
		DeleteResult *bool `json:"DeleteResult"`
	}
	if err := t.ssl("").Call(ctx, "DeleteCertificate", map[string]string{"CertificateId": oldID}, &response); err != nil {
		var providerError *dnsgo.Error
		if dnsgo.IsCode(err, dnsgo.CodeNotFound) || errors.As(err, &providerError) &&
			providerError.VendorCode == "FailedOperation.CertificateNotFound" {
			return nil
		}
		return fmt.Errorf("Tencent old certificate deletion failed: %w", err)
	}
	if response.DeleteResult == nil || !*response.DeleteResult {
		return &dnsgo.Error{Provider: t.Kind(), Operation: "delete_old_certificate", Code: dnsgo.CodeResultUnknown,
			Message: "Tencent old certificate deletion did not confirm success"}
	}
	return nil
}

func (t *Tencent) pollUpdate(ctx context.Context, result Result) (Result, error) {
	recordID := result.Metadata["deploy_record_id"]
	var record TencentDeployRecord
	var err error
	if result.Metadata["mode"] == "update" {
		record, err = t.inspectUploadUpdateRecord(ctx, recordID)
	} else {
		record, err = t.inspectUpdateRecord(ctx, recordID)
	}
	if err != nil {
		return result, err
	}
	if record.TotalCount == 0 || record.RunningTotalCount > 0 || record.PendingTotalCount > 0 {
		return result, nil
	}
	if record.FailedTotalCount > 0 {
		return result, &dnsgo.Error{Provider: t.Kind(), Operation: "poll_update", Code: dnsgo.CodeConflict,
			Message: "Tencent certificate update task reported failed resources"}
	}
	if record.SuccessTotalCount != record.TotalCount || len(record.Details) != record.TotalCount {
		return result, &dnsgo.Error{Provider: t.Kind(), Operation: "poll_update", Code: dnsgo.CodeResultUnknown,
			Message: "Tencent certificate update task has incomplete details"}
	}
	for _, detail := range record.Details {
		if detail.Status != 1 || result.Metadata["mode"] == "update_new" && detail.CertID != result.Location ||
			result.Metadata["mode"] == "update" && detail.OldCertID != result.Location {
			return result, &dnsgo.Error{Provider: t.Kind(), Operation: "poll_update", Code: dnsgo.CodeConflict,
				Message: "Tencent certificate update detail does not match this certificate"}
		}
	}
	if result.Metadata["mode"] == "update_new" && result.Metadata["delete_old_cert"] == "true" {
		result.Metadata["cleanup_pending"] = "true"
		return result, nil
	}
	result.Pending = false
	return result, nil
}

func (t *Tencent) inspectUpdateRecord(ctx context.Context, recordID string) (TencentDeployRecord, error) {
	result := TencentDeployRecord{}
	for offset := 0; offset < 20000; offset += 200 {
		var page struct {
			TotalCount        int `json:"TotalCount"`
			SuccessTotalCount int `json:"SuccessTotalCount"`
			FailedTotalCount  int `json:"FailedTotalCount"`
			RunningTotalCount int `json:"RunningTotalCount"`
			PendingTotalCount int `json:"PendingTotalCount"`
			Groups            []struct {
				List []TencentDeployDetail `json:"List"`
			} `json:"RecordDetailList"`
		}
		if err := t.ssl("").Call(ctx, "DescribeHostUpdateRecordDetail", map[string]any{
			"DeployRecordId": recordID, "Limit": 200, "Offset": offset,
		}, &page); err != nil {
			return TencentDeployRecord{}, err
		}
		result.TotalCount, result.SuccessTotalCount, result.FailedTotalCount =
			page.TotalCount, page.SuccessTotalCount, page.FailedTotalCount
		result.RunningTotalCount, result.PendingTotalCount = page.RunningTotalCount, page.PendingTotalCount
		added := 0
		for _, group := range page.Groups {
			result.Details = append(result.Details, group.List...)
			added += len(group.List)
		}
		if page.TotalCount == 0 || len(result.Details) >= page.TotalCount {
			return result, nil
		}
		if added == 0 {
			return TencentDeployRecord{}, &dnsgo.Error{Provider: t.Kind(), Operation: "inspect_update",
				Code: dnsgo.CodeResultUnknown, Message: "Tencent update detail pagination is incomplete"}
		}
	}
	return TencentDeployRecord{}, &dnsgo.Error{Provider: t.Kind(), Operation: "inspect_update", Code: dnsgo.CodeResultUnknown,
		Message: "Tencent update details exceeded 100 pages"}
}

func (t *Tencent) inspectUploadUpdateRecord(ctx context.Context, recordID string) (TencentDeployRecord, error) {
	result := TencentDeployRecord{}
	for offset := 0; offset < 20000; offset += 200 {
		var page struct {
			Records []struct {
				TotalCount        int `json:"TotalCount"`
				SuccessTotalCount int `json:"SuccessTotalCount"`
				FailedTotalCount  int `json:"FailedTotalCount"`
				RunningTotalCount int `json:"RunningTotalCount"`
				PendingTotalCount int `json:"PendingTotalCount"`
				Groups            []struct {
					List []TencentDeployDetail `json:"List"`
				} `json:"RecordDetailList"`
			} `json:"DeployRecordDetail"`
		}
		if err := t.ssl("").Call(ctx, "DescribeHostUploadUpdateRecordDetail", map[string]any{
			"DeployRecordId": recordID, "Limit": 200, "Offset": offset,
		}, &page); err != nil {
			return TencentDeployRecord{}, err
		}
		added := 0
		for _, item := range page.Records {
			result.TotalCount += item.TotalCount
			result.SuccessTotalCount += item.SuccessTotalCount
			result.FailedTotalCount += item.FailedTotalCount
			result.RunningTotalCount += item.RunningTotalCount
			result.PendingTotalCount += item.PendingTotalCount
			for _, group := range item.Groups {
				result.Details = append(result.Details, group.List...)
				added += len(group.List)
			}
		}
		if len(page.Records) == 0 || added == 0 || len(page.Records) < 200 {
			return result, nil
		}
	}
	return TencentDeployRecord{}, &dnsgo.Error{Provider: t.Kind(), Operation: "inspect_upload_update",
		Code: dnsgo.CodeResultUnknown, Message: "Tencent upload-update details exceeded 100 pages"}
}
