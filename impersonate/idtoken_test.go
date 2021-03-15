package impersonate

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"testing"

	"google.golang.org/api/option"
)

func TestIDTokenSource(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name            string
		aud             string
		targetPrincipal string
		wantErr         bool
	}{
		{
			name:            "missing aud",
			targetPrincipal: "foo@project-id.iam.gserviceaccount.com",
			wantErr:         true,
		},
		{
			name:    "missing targetPrincipal",
			aud:     "http://example.com/",
			wantErr: true,
		},
		{
			name:            "works",
			aud:             "http://example.com/",
			targetPrincipal: "foo@project-id.iam.gserviceaccount.com",
			wantErr:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &http.Client{
				Transport: RoundTripFn(func(req *http.Request) *http.Response {
					resp := generateIDTokenResponse{
						Token: "token",
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
				}),
			}
			ts, err := IDTokenSource(ctx, IDTokenConfig{
				Audience:        tt.aud,
				TargetPrincipal: tt.targetPrincipal,
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
