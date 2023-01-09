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

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

type mockCredentialsProvider struct{}

func (mockCredentialsProvider) Retrieve(context.Context) (aws.Credentials, error) {
	return aws.Credentials{
		AccessKeyID: "AKID", SecretAccessKey: "SECRET", SessionToken: "SESSION",
		Source: "mock credentials",
	}, nil
}

// Client provides interface to query AWS Secrets Manager service.
type Client interface {
	GetSecret(string) (map[string]interface{}, error)
	GetSecretByKey(string, string) (string, error)
	SetMockClient(aws.HTTPClient)
	SetMockCredentialsProvider(aws.CredentialsProvider)
}

type clientConfig struct {
	Region string
}

type client struct {
	config        *clientConfig
	serviceConfig aws.Config
	serviceClient *secretsmanager.Client
}

// NewClient returns an instance of Client.
func NewClient(region string) (Client, error) {
	c := &client{
		config: &clientConfig{
			Region: region,
		},
	}
	serviceConfig, err := config.LoadDefaultConfig(
		context.TODO(),
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
func (c *client) GetSecret(path string) (map[string]interface{}, error) {
	if c.serviceClient == nil {
		c.serviceClient = secretsmanager.NewFromConfig(c.serviceConfig)
	}
	input := &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(path),
		VersionStage: aws.String("AWSCURRENT"),
	}
	result, err := c.serviceClient.GetSecretValue(context.TODO(), input)
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
func (c *client) GetSecretByKey(path string, key string) (string, error) {
	secret, err := c.GetSecret(path)
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
