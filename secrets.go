// Copyright 2022 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

var (
	awsRegionRgx *regexp.Regexp = regexp.MustCompile(`\w{2}-\w+-\d`)
)

// MockCredentialsProvider mocks AWS credentials provider.
type MockCredentialsProvider struct{}

// Retrieve returns mock AWS credentials.
func (MockCredentialsProvider) Retrieve(context.Context) (aws.Credentials, error) {
	return aws.Credentials{
		AccessKeyID: "AKID", SecretAccessKey: "SECRET", SessionToken: "SESSION",
		Source: "mock credentials",
	}, nil
}

// Client provides interface to query AWS Secrets Manager service.
type Client interface {
	GetSecret(context.Context, string) (map[string]interface{}, error)
	GetSecretByKey(context.Context, string, string) (interface{}, error)
	SetMockClient(aws.HTTPClient)
	SetMockCredentialsProvider(aws.CredentialsProvider)
	GetConfig(context.Context) map[string]interface{}
}

type clientConfig struct {
	ID       string `json:"id,omitempty" xml:"id,omitempty" yaml:"id,omitempty"`
	Region   string `json:"region,omitempty" xml:"region,omitempty" yaml:"region,omitempty"`
	Provider string `json:"provider,omitempty" xml:"provider,omitempty" yaml:"provider,omitempty"`
}

type client struct {
	config        *clientConfig
	serviceConfig aws.Config
	serviceClient *secretsmanager.Client
}

// NewClient returns an instance of Client.
func NewClient(ctx context.Context, id string, region string) (Client, error) {
	c := &client{
		config: &clientConfig{
			ID:       id,
			Region:   region,
			Provider: "aws_secrets_manager",
		},
	}

	if region != "" {
		if awsRegionRgx.MatchString(region) == false {
			return nil, fmt.Errorf("malformed %q region", region)
		}
	}

	serviceConfig, err := config.LoadDefaultConfig(
		ctx,
		config.WithRegion(c.config.Region),
		// config.WithClientLogMode(aws.LogRetries|aws.LogRequestWithBody|aws.LogResponseWithBody|aws.LogRequestEventMessage|aws.LogResponseEventMessage|aws.LogSigning),
	)
	if err != nil {
		return nil, err
	}
	c.serviceConfig = serviceConfig
	return c, nil
}

// GetSecret returns the key-value map of the stored secret.
func (c *client) GetSecret(ctx context.Context, path string) (map[string]interface{}, error) {
	if c.serviceClient == nil {
		c.serviceClient = secretsmanager.NewFromConfig(c.serviceConfig)
	}
	input := &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(path),
		VersionStage: aws.String("AWSCURRENT"),
	}
	result, err := c.serviceClient.GetSecretValue(ctx, input)
	if err != nil {
		return nil, err
	}

	if result.SecretString == nil {
		return nil, errors.New("SecretString not found in response")
	}

	var secretString string = *result.SecretString
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(secretString), &m); err != nil {
		return nil, err
	}

	return m, nil
}

// GetSecret returns the key-value map of the stored secret.
func (c *client) GetSecretByKey(ctx context.Context, path string, key string) (interface{}, error) {
	secret, err := c.GetSecret(ctx, path)
	if err != nil {
		return "", err
	}
	value, exists := secret[key]
	if !exists {
		return "", fmt.Errorf("key %q not found in %q secret", key, path)
	}
	return value.(string), nil
}

// SetMockClient configures mock HTTP client.
func (c *client) SetMockClient(mockClient aws.HTTPClient) {
	c.serviceConfig.HTTPClient = mockClient
}

// SetMockCredentialsProvider configures mock AWS credentials provider.
func (c *client) SetMockCredentialsProvider(mockProvider aws.CredentialsProvider) {
	c.serviceConfig.Credentials = mockProvider
}

// GetConfig returns client configuration.
func (c *client) GetConfig(_ context.Context) map[string]interface{} {
	cfg := map[string]interface{}{
		"id":       c.config.ID,
		"region":   c.config.Region,
		"provider": c.config.Provider,
	}
	return cfg
}
