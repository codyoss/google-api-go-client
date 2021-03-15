package impersonate

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"testing"
	"time"

	"google.golang.org/api/option"
)

func TestTokenSource(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name            string
		targetPrincipal string
		scopes          []string
		lifetime        time.Duration
		wantErr         bool
	}{
		{
			name:    "missing targetPrincipal",
			wantErr: true,
		},
		{
			name:            "missing scopes",
			targetPrincipal: "foo@project-id.iam.gserviceaccount.com",
			wantErr:         true,
		},
		{
			name:            "lifetime over max",
			targetPrincipal: "foo@project-id.iam.gserviceaccount.com",
			scopes:          []string{"scope"},
			lifetime:        3601 * time.Second,
			wantErr:         true,
		},
		{
			name:            "lifetime over max",
			targetPrincipal: "foo@project-id.iam.gserviceaccount.com",
			scopes:          []string{"scope"},
			wantErr:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &http.Client{
				Transport: RoundTripFn(func(req *http.Request) *http.Response {
					log.Println(req.URL.Path)
					if strings.Contains(req.URL.Path, "generateAccessToken") {
						resp := generateAccessTokenResp{
							AccessToken: "token",
							ExpireTime:  time.Now().Format(time.RFC3339),
						}
						b, err := json.Marshal(&resp)
						if err != nil {
							t.Fatalf("unable to marshal response: %v", err)
						}
						return &http.Response{
							StatusCode: 200,
							Body:       ioutil.NopCloser(bytes.NewReader(b)),
							Header:     make(http.Header),
						}
					}
					return nil
				}),
			}
			ts, err := TokenSource(ctx, Config{
				TargetPrincipal: tt.targetPrincipal,
				Scopes:          tt.scopes,
				Lifetime:        tt.lifetime,
			}, option.WithHTTPClient(client))
			if tt.wantErr && err != nil {
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ts.Token(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type RoundTripFn func(req *http.Request) *http.Response

func (f RoundTripFn) RoundTrip(req *http.Request) (*http.Response, error) { return f(req), nil }
