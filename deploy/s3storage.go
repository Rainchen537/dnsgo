package deploy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type S3Storage struct {
	client   *s3.Client
	bucket   string
	certPath string
	keyPath  string
}

func init() {
	register("s3storage", func(config Config) (Target, error) {
		if config.Endpoint == "" {
			config.Endpoint = config.Values["endpoint"]
		}
		endpoint, err := targetEndpoint(config, "")
		if err != nil {
			return nil, err
		}
		keyID, secret := strings.TrimSpace(config.Values["AccessKeyId"]), strings.TrimSpace(config.Values["SecretAccessKey"])
		bucket := strings.TrimSpace(config.Values["bucket"])
		certPath, keyPath := strings.Trim(config.Values["cert_path"], "/"), strings.Trim(config.Values["key_path"], "/")
		if keyID == "" || secret == "" || bucket == "" || certPath == "" || keyPath == "" || certPath == keyPath {
			return nil, errors.New("S3 credentials, bucket and distinct certificate/key paths are required")
		}
		region := strings.TrimSpace(config.Values["region"])
		if region == "" {
			region = "us-east-1"
		}
		awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(), awsconfig.WithRegion(region),
			awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(keyID, secret, "")), awsconfig.WithHTTPClient(client(config)))
		if err != nil {
			return nil, errors.New("S3 SDK configuration failed")
		}
		api := s3.NewFromConfig(awsCfg, func(options *s3.Options) {
			options.BaseEndpoint = aws.String(endpoint)
			options.UsePathStyle = true
		})
		return &S3Storage{client: api, bucket: bucket, certPath: certPath, keyPath: keyPath}, nil
	})
}

func (t *S3Storage) Kind() string { return "s3storage" }

func (t *S3Storage) Check(ctx context.Context) error {
	_, err := t.client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return errors.New("S3 bucket listing failed")
	}
	return nil
}

func (t *S3Storage) Deploy(ctx context.Context, material Material) (Result, error) {
	if _, err := certificate(material); err != nil {
		return Result{}, err
	}
	result := Result{Target: t.Kind(), Location: fmt.Sprintf("s3://%s/%s", t.bucket, t.certPath)}
	if _, err := t.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(t.bucket), Key: aws.String(t.certPath), Body: bytes.NewReader(material.FullChainPEM), ContentType: aws.String("application/x-pem-file"),
	}); err != nil {
		return result, errors.New("S3 certificate upload failed")
	}
	result.Written = true
	if _, err := t.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(t.bucket), Key: aws.String(t.keyPath), Body: bytes.NewReader(material.PrivateKeyPEM), ContentType: aws.String("application/x-pem-file"),
	}); err != nil {
		return result, errors.New("S3 private key upload failed after certificate upload")
	}
	return result, nil
}

var _ Target = (*S3Storage)(nil)
