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
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"github.com/google/go-cmp/cmp"
)

// packMapToJSON converts a map to a JSON string.
func packMapToJSON(t *testing.T, m map[string]interface{}) string {
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("failed to marshal %v: %v", m, err)
	}
	return string(b)
}

func TestGetSecret(t *testing.T) {
	jsmith := map[string]interface{}{
		"api_key":  "bcrypt:10:$2a$10$TEQ7ZG9cAdWwhQK36orCGOlokqQA55ddE0WEsl00oLZh567okdcZ6",
		"email":    "jsmith@localhost.localdomain",
		"name":     "John Smith",
		"password": "bcrypt:10:$2a$10$iqq53VjdCwknBSBrnyLd9OH1Mfh6kqPezMMy6h6F41iLdVDkj13I6",
		"username": "jsmith",
	}

	accessToken := map[string]interface{}{
		"id":    "0",
		"usage": "sign-verify",
		"value": "b006d65b-c923-46a1-8da1-7d52558508fe",
	}

	testcases := []struct {
		name       string
		path       string
		region     string
		mockClient aws.HTTPClient
		want       map[string]interface{}
		shouldErr  bool
		err        error
	}{
		{
			name:   "test valid user secret",
			path:   "authcrunch/caddy/jsmith",
			region: "us-east-1",
			want:   jsmith,
			mockClient: smithyhttp.ClientDoFunc(func(r *http.Request) (*http.Response, error) {
				// t.Logf("received HTTP request")
				// dump, err := httputil.DumpRequest(r, true)
				// if err != nil {
				// 	t.Logf("failed dumping HTTP request: %v", err)
				// }
				// t.Logf("%q", dump)
				response := packMapToJSON(t, map[string]interface{}{
					"SecretString": packMapToJSON(t, jsmith),
				})
				return &http.Response{
					StatusCode: 200,
					Header:     http.Header{},
					Body:       ioutil.NopCloser(strings.NewReader(response)),
				}, nil
			}),
		},
		{
			name:   "test valid access token secret",
			path:   "authcrunch/caddy/access_token",
			region: "us-east-1",
			want:   accessToken,
			mockClient: smithyhttp.ClientDoFunc(func(r *http.Request) (*http.Response, error) {
				response := packMapToJSON(t, map[string]interface{}{
					"SecretString": packMapToJSON(t, accessToken),
				})
				return &http.Response{
					StatusCode: 200,
					Header:     http.Header{},
					Body:       ioutil.NopCloser(strings.NewReader(response)),
				}, nil
			}),
		},
		{
			name:   "test empty response",
			path:   "authcrunch/caddy/empty",
			region: "us-east-1",
			mockClient: smithyhttp.ClientDoFunc(func(r *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: 200,
					Header:     http.Header{},
					Body:       ioutil.NopCloser(strings.NewReader(`{}`)),
				}, nil
			}),
			shouldErr: true,
			err:       errors.New("SecretString not found in response"),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewClient(tc.region)
			if err != nil {
				t.Fatalf("unxpected error during client initialization: %v", err)
			}

			c.SetMockClient(tc.mockClient)

			got, err := c.GetSecret(tc.path)

			if err != nil {
				if !tc.shouldErr {
					t.Fatalf("expected success, got: %v", err)
				}
				if diff := cmp.Diff(err.Error(), tc.err.Error()); diff != "" {
					t.Fatalf("unexpected error: %v, want: %v", err, tc.err)
				}
				return
			}
			if tc.shouldErr {
				t.Fatalf("unexpected success, want: %v", tc.err)
			}

			if diff := cmp.Diff(packMapToJSON(t, tc.want), packMapToJSON(t, got)); diff != "" {
				t.Logf("JSON: %v", packMapToJSON(t, got))
				t.Errorf("GetSecret() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestGetSecretByKey(t *testing.T) {
	jsmith := map[string]interface{}{
		"api_key":  "bcrypt:10:$2a$10$TEQ7ZG9cAdWwhQK36orCGOlokqQA55ddE0WEsl00oLZh567okdcZ6",
		"email":    "jsmith@localhost.localdomain",
		"name":     "John Smith",
		"password": "bcrypt:10:$2a$10$iqq53VjdCwknBSBrnyLd9OH1Mfh6kqPezMMy6h6F41iLdVDkj13I6",
		"username": "jsmith",
	}

	testcases := []struct {
		name       string
		path       string
		key        string
		region     string
		mockClient aws.HTTPClient
		want       string
		shouldErr  bool
		err        error
	}{
		{
			name:   "test valid user secret by key",
			path:   "authcrunch/caddy/jsmith",
			region: "us-east-1",
			key:    "name",
			want:   "John Smith",
			mockClient: smithyhttp.ClientDoFunc(func(r *http.Request) (*http.Response, error) {
				response := packMapToJSON(t, map[string]interface{}{
					"SecretString": packMapToJSON(t, jsmith),
				})
				return &http.Response{
					StatusCode: 200,
					Header:     http.Header{},
					Body:       ioutil.NopCloser(strings.NewReader(response)),
				}, nil
			}),
		},
		{
			name:   "test key not found",
			path:   "authcrunch/caddy/jsmith",
			region: "us-east-1",
			key:    "foo",
			mockClient: smithyhttp.ClientDoFunc(func(r *http.Request) (*http.Response, error) {
				response := packMapToJSON(t, map[string]interface{}{
					"SecretString": packMapToJSON(t, jsmith),
				})
				return &http.Response{
					StatusCode: 200,
					Header:     http.Header{},
					Body:       ioutil.NopCloser(strings.NewReader(response)),
				}, nil
			}),
			shouldErr: true,
			err:       fmt.Errorf("key %q not found in %q secret", "foo", "authcrunch/caddy/jsmith"),
		},
		{
			name:   "test secret not found",
			path:   "authcrunch/caddy/foo",
			region: "us-east-1",
			key:    "bar",
			mockClient: smithyhttp.ClientDoFunc(func(r *http.Request) (*http.Response, error) {
				response := packMapToJSON(t, map[string]interface{}{
					"__type":  "ResourceNotFoundException",
					"Message": "Secrets Manager can't find the specified secret.",
				})

				return &http.Response{
					StatusCode: 400,
					Header: http.Header{
						"X-Amzn-Requestid": []string{"524b9962-6854-4b5c-aa53-81759ef610dd"},
					},
					Body: ioutil.NopCloser(strings.NewReader(response)),
				}, nil
			}),
			shouldErr: true,
			err: fmt.Errorf("operation error Secrets Manager: GetSecretValue, https response error StatusCode: %d, RequestID: %s, %s: %s",
				400, "524b9962-6854-4b5c-aa53-81759ef610dd", "ResourceNotFoundException", "Secrets Manager can't find the specified secret.",
			),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewClient(tc.region)
			if err != nil {
				t.Fatalf("unxpected error during client initialization: %v", err)
			}

			c.SetMockClient(tc.mockClient)

			got, err := c.GetSecretByKey(tc.path, tc.key)
			if err != nil {
				if !tc.shouldErr {
					t.Fatalf("expected success, got: %v", err)
				}
				if diff := cmp.Diff(err.Error(), tc.err.Error()); diff != "" {
					t.Logf("got:  %v", err)
					t.Logf("want: %v", tc.err)
					t.Fatalf("unexpected error mismatch (-want +got):\n%s", diff)
				}
				return
			}
			if tc.shouldErr {
				t.Fatalf("unexpected success, want: %v", tc.err)
			}

			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("GetSecret() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
