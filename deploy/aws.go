package deploy

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	cloudfronttypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/rainchen537/dnsgo"
)

type AWS struct {
	acm          *acm.Client
	cloudfront   *cloudfront.Client
	iam          *iam.Client
	product      string
	acmARN       string
	priorCertARN string
	distribution string
}

func init() {
	register("aws", func(config Config) (Target, error) {
		keyID, secret := strings.TrimSpace(config.Values["AccessKeyId"]), strings.TrimSpace(config.Values["SecretAccessKey"])
		if keyID == "" || secret == "" {
			return nil, errors.New("AWS access key ID and secret are required")
		}
		product := strings.TrimSpace(config.Values["product"])
		if product == "" {
			product = "cloudfront"
		}
		if product != "acm" && product != "cloudfront" {
			return nil, errors.New("AWS certificate product must be acm or cloudfront")
		}
		acmARN, distribution := strings.TrimSpace(config.Values["acm_arn"]), strings.TrimSpace(config.Values["distribution_id"])
		if product == "acm" && acmARN == "" {
			return nil, errors.New("AWS ACM certificate ARN is required")
		}
		if product == "cloudfront" && distribution == "" {
			return nil, errors.New("AWS CloudFront distribution ID is required")
		}
		awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(), awsconfig.WithRegion("us-east-1"),
			awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(keyID, secret, config.Values["SessionToken"])),
			awsconfig.WithHTTPClient(client(config)))
		if err != nil {
			return nil, errors.New("AWS SDK configuration failed")
		}
		return &AWS{acm: acm.NewFromConfig(awsCfg), cloudfront: cloudfront.NewFromConfig(awsCfg), iam: iam.NewFromConfig(awsCfg),
			product: product, acmARN: acmARN, priorCertARN: strings.TrimSpace(config.Values["cert_id"]), distribution: distribution}, nil
	})
}

func (t *AWS) Kind() string { return "aws" }

func (t *AWS) Check(ctx context.Context) error {
	_, err := t.iam.GetUser(ctx, &iam.GetUserInput{})
	if err != nil {
		return errors.New("AWS IAM access check failed")
	}
	return nil
}

func (t *AWS) Deploy(ctx context.Context, material Material) (Result, error) {
	if _, err := certificate(material); err != nil {
		return Result{}, err
	}
	leaf, chain, err := splitCertificateChain(material.FullChainPEM)
	if err != nil {
		return Result{}, err
	}
	arn := t.priorCertARN
	if t.product == "acm" {
		arn = t.acmARN
	}
	if arn != "" {
		current, err := t.acm.GetCertificate(ctx, &acm.GetCertificateInput{CertificateArn: aws.String(arn)})
		if err == nil && strings.TrimSpace(aws.ToString(current.Certificate)) == strings.TrimSpace(string(leaf)) {
			if t.product == "acm" {
				return Result{Target: t.Kind(), Location: arn, Written: false}, nil
			}
		} else if err != nil {
			return Result{}, errors.New("AWS ACM certificate lookup failed")
		} else {
			arn = ""
		}
	}
	result := Result{Target: t.Kind(), Location: arn}
	if arn == "" || t.product == "acm" {
		input := &acm.ImportCertificateInput{Certificate: leaf, PrivateKey: material.PrivateKeyPEM}
		if len(chain) > 0 {
			input.CertificateChain = chain
		}
		if t.product == "acm" {
			input.CertificateArn = aws.String(t.acmARN)
		}
		result.Written = true // ImportCertificate may succeed without a response.
		uploaded, err := t.acm.ImportCertificate(ctx, input)
		if err != nil {
			return result, errors.New("AWS ACM certificate import failed")
		}
		arn = aws.ToString(uploaded.CertificateArn)
		result.Location = arn
		if arn == "" {
			return result, errors.New("AWS ACM import returned no certificate ARN")
		}
	}
	if t.product == "acm" {
		return result, nil
	}
	if err := waitContext(ctx, 500*time.Millisecond); err != nil {
		return result, err
	}
	configuration, err := t.cloudfront.GetDistributionConfig(ctx, &cloudfront.GetDistributionConfigInput{Id: aws.String(t.distribution)})
	if err != nil || configuration.DistributionConfig == nil || configuration.ETag == nil {
		return result, errors.New("AWS CloudFront distribution configuration lookup failed")
	}
	viewer := configuration.DistributionConfig.ViewerCertificate
	if viewer == nil {
		viewer = &cloudfronttypes.ViewerCertificate{}
	}
	if aws.ToString(viewer.ACMCertificateArn) == arn && aws.ToBool(viewer.CloudFrontDefaultCertificate) == false {
		distribution, err := t.cloudfront.GetDistribution(ctx, &cloudfront.GetDistributionInput{Id: aws.String(t.distribution)})
		if err != nil || distribution.Distribution == nil {
			return result, errors.New("AWS CloudFront distribution status lookup failed")
		}
		result.Metadata = map[string]string{"distribution_id": t.distribution,
			"distribution_status": aws.ToString(distribution.Distribution.Status)}
		result.Pending = aws.ToString(distribution.Distribution.Status) != "Deployed"
		return result, nil
	}
	viewer.ACMCertificateArn = aws.String(arn)
	viewer.CloudFrontDefaultCertificate = aws.Bool(false)
	viewer.IAMCertificateId = nil
	viewer.Certificate = nil
	viewer.CertificateSource = ""
	if viewer.MinimumProtocolVersion == "" {
		viewer.MinimumProtocolVersion = cloudfronttypes.MinimumProtocolVersionTLSv122021
	}
	if viewer.SSLSupportMethod == "" {
		viewer.SSLSupportMethod = cloudfronttypes.SSLSupportMethodSniOnly
	}
	configuration.DistributionConfig.ViewerCertificate = viewer
	result.Written = true // CloudFront may accept the update before a timeout.
	updated, err := t.cloudfront.UpdateDistribution(ctx, &cloudfront.UpdateDistributionInput{
		Id: aws.String(t.distribution), IfMatch: configuration.ETag, DistributionConfig: configuration.DistributionConfig,
	})
	if err != nil {
		return result, errors.New("AWS CloudFront distribution update failed")
	}
	if updated.Distribution != nil {
		result.Metadata = map[string]string{"distribution_id": t.distribution,
			"distribution_status": aws.ToString(updated.Distribution.Status)}
	}
	result.Pending = result.Metadata == nil || result.Metadata["distribution_status"] != "Deployed"
	return result, nil
}

func (t *AWS) Poll(ctx context.Context, result Result) (Result, error) {
	if !result.Pending || t.product != "cloudfront" || result.Location == "" ||
		result.Metadata != nil && result.Metadata["distribution_id"] != "" && result.Metadata["distribution_id"] != t.distribution {
		return result, &dnsgo.Error{Provider: t.Kind(), Operation: "poll_deployment", Code: dnsgo.CodeConflict,
			Message: "AWS CloudFront pending result does not match configuration"}
	}
	distribution, err := t.cloudfront.GetDistribution(ctx, &cloudfront.GetDistributionInput{Id: aws.String(t.distribution)})
	if err != nil {
		return result, errors.New("AWS CloudFront distribution status lookup failed")
	}
	if distribution.Distribution == nil || distribution.Distribution.DistributionConfig == nil ||
		distribution.Distribution.DistributionConfig.ViewerCertificate == nil {
		return result, &dnsgo.Error{Provider: t.Kind(), Operation: "poll_deployment", Code: dnsgo.CodeResultUnknown,
			Message: "AWS CloudFront distribution returned incomplete certificate details"}
	}
	viewer := distribution.Distribution.DistributionConfig.ViewerCertificate
	if aws.ToString(viewer.ACMCertificateArn) != result.Location || aws.ToBool(viewer.CloudFrontDefaultCertificate) {
		return result, &dnsgo.Error{Provider: t.Kind(), Operation: "poll_deployment", Code: dnsgo.CodeConflict,
			Message: "AWS CloudFront distribution uses a different certificate"}
	}
	status := aws.ToString(distribution.Distribution.Status)
	if result.Metadata == nil {
		result.Metadata = map[string]string{}
	}
	result.Metadata["distribution_id"] = t.distribution
	result.Metadata["distribution_status"] = status
	if status == "Deployed" {
		result.Pending = false
	} else if status != "InProgress" {
		return result, &dnsgo.Error{Provider: t.Kind(), Operation: "poll_deployment", Code: dnsgo.CodeResultUnknown,
			Message: "AWS CloudFront distribution has an unknown deployment status"}
	}
	return result, nil
}

func splitCertificateChain(fullchain []byte) ([]byte, []byte, error) {
	var leaf, chain bytes.Buffer
	for len(bytes.TrimSpace(fullchain)) > 0 {
		block, rest := pem.Decode(fullchain)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, nil, errors.New("invalid PEM certificate chain")
		}
		encoded := pem.EncodeToMemory(block)
		if leaf.Len() == 0 {
			leaf.Write(encoded)
		} else {
			chain.Write(encoded)
		}
		fullchain = rest
	}
	if leaf.Len() == 0 {
		return nil, nil, errors.New("certificate chain is empty")
	}
	return leaf.Bytes(), chain.Bytes(), nil
}

var _ Target = (*AWS)(nil)
