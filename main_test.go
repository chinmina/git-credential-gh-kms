package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

var testKey = sync.OnceValue(func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
})

type fakeSigner struct {
	in  *kms.SignInput
	err error
}

func (f *fakeSigner) Sign(_ context.Context, in *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	f.in = in
	if f.err != nil {
		return nil, f.err
	}
	sum := sha256.Sum256(in.Message)
	sig, err := rsa.SignPKCS1v15(nil, testKey(), crypto.SHA256, sum[:])
	if err != nil {
		return nil, err
	}
	return &kms.SignOutput{Signature: sig}, nil
}

func TestReadRequest(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want map[string]string
	}{
		{"basic", "protocol=https\nhost=github.com\n", map[string]string{"protocol": "https", "host": "github.com"}},
		{"stops at blank line", "protocol=https\n\nhost=github.com\n", map[string]string{"protocol": "https"}},
		{"skips lines without =", "garbage\nhost=github.com\n", map[string]string{"host": "github.com"}},
		{"last duplicate wins", "host=a\nhost=b\n", map[string]string{"host": "b"}},
		{"value may contain =", "path=a=b\n", map[string]string{"path": "a=b"}},
		{"empty", "", map[string]string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readRequest(strings.NewReader(tt.in))
			if err != nil || !maps.Equal(got, tt.want) {
				t.Errorf("got %v, %v, want %v", got, err, tt.want)
			}
		})
	}
}

func TestReadRequestLineTooLong(t *testing.T) {
	in := "wwwauth[]=" + strings.Repeat("a", bufio.MaxScanTokenSize) + "\nhost=github.com\n"
	if _, err := readRequest(strings.NewReader(in)); err == nil {
		t.Error("expected error for oversized line")
	}
}

func setValidEnv(t *testing.T) {
	t.Helper()
	t.Setenv("GH_APP_ID", "Iv1.abc")
	t.Setenv("GH_INSTALLATION_ID", "42")
	t.Setenv("GH_KMS_KEY_ID", "alias/github-app")
	t.Setenv("GH_HOST", "")
	t.Setenv("GH_API_URL", "")
	t.Setenv("GH_TOKEN_REQUEST", "")
}

func TestLoadValid(t *testing.T) {
	setValidEnv(t)

	s, err := load(defaultHost)
	if err != nil {
		t.Fatal(err)
	}
	if s.appID != "Iv1.abc" || s.installationID != 42 || s.keyID != "alias/github-app" {
		t.Errorf("unexpected settings: %+v", s)
	}
	if s.api.String() != defaultAPI {
		t.Errorf("api = %s, want %s", s.api, defaultAPI)
	}
	if string(s.body) != defaultBody {
		t.Errorf("body = %s, want %s", s.body, defaultBody)
	}

	t.Setenv("GH_TOKEN_REQUEST", `{"repositories":["r"]}`)
	if s, err = load(defaultHost); err != nil || string(s.body) != `{"repositories":["r"]}` {
		t.Errorf("override: body = %s, err = %v", s.body, err)
	}
}

func TestLoadAPIURLFollowsHost(t *testing.T) {
	setValidEnv(t)
	s, err := load("ghe.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if want := "https://ghe.example.com/api/v3"; s.api.String() != want {
		t.Errorf("api = %s, want %s", s.api, want)
	}

	t.Setenv("GH_API_URL", "https://api.ghe.example.com")
	if s, err = load("ghe.example.com"); err != nil || s.api.Host != "api.ghe.example.com" {
		t.Errorf("explicit GH_API_URL not used: %v, %v", s.api, err)
	}
}

func TestLoadErrors(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		wantErr []string
	}{
		{
			name:    "all required missing",
			env:     map[string]string{"GH_APP_ID": "", "GH_INSTALLATION_ID": "", "GH_KMS_KEY_ID": ""},
			wantErr: []string{"GH_APP_ID is required", "GH_INSTALLATION_ID is required", "GH_KMS_KEY_ID is required"},
		},
		{name: "installation id zero", env: map[string]string{"GH_INSTALLATION_ID": "0"}, wantErr: []string{"not a positive integer"}},
		{name: "installation id negative", env: map[string]string{"GH_INSTALLATION_ID": "-1"}, wantErr: []string{"not a positive integer"}},
		{name: "installation id non-numeric", env: map[string]string{"GH_INSTALLATION_ID": "abc"}, wantErr: []string{"not a positive integer"}},
		{name: "api url http", env: map[string]string{"GH_API_URL": "http://api.github.com"}, wantErr: []string{"absolute https URL"}},
		{name: "api url relative", env: map[string]string{"GH_API_URL": "api.github.com"}, wantErr: []string{"absolute https URL"}},
		{name: "api url no host", env: map[string]string{"GH_API_URL": "https:///api"}, wantErr: []string{"absolute https URL"}},
		{name: "api url unparseable", env: map[string]string{"GH_API_URL": "https://[::1"}, wantErr: []string{"GH_API_URL:"}},
		{name: "api url userinfo", env: map[string]string{"GH_API_URL": "https://user@api.github.com"}, wantErr: []string{"absolute https URL"}},
		{name: "api url query", env: map[string]string{"GH_API_URL": "https://api.github.com?x=1"}, wantErr: []string{"absolute https URL"}},
		{name: "api url fragment", env: map[string]string{"GH_API_URL": "https://api.github.com#f"}, wantErr: []string{"absolute https URL"}},
		{name: "token request invalid", env: map[string]string{"GH_TOKEN_REQUEST": "{"}, wantErr: []string{"GH_TOKEN_REQUEST"}},
		{name: "token request array", env: map[string]string{"GH_TOKEN_REQUEST": "[1]"}, wantErr: []string{"GH_TOKEN_REQUEST"}},
		{name: "token request trailing data", env: map[string]string{"GH_TOKEN_REQUEST": `{} {}`}, wantErr: []string{"GH_TOKEN_REQUEST"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setValidEnv(t)
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			_, err := load(defaultHost)
			if err == nil {
				t.Fatal("expected error")
			}
			for _, want := range tt.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not contain %q", err, want)
				}
			}
		})
	}
}

func TestSignJWT(t *testing.T) {
	f := &fakeSigner{}
	before := time.Now().Unix()
	jwt, err := signJWT(t.Context(), f, "Iv1.abc", "alias/k")
	if err != nil {
		t.Fatal(err)
	}

	if got := aws.ToString(f.in.KeyId); got != "alias/k" {
		t.Errorf("KeyId = %q", got)
	}
	if f.in.MessageType != types.MessageTypeRaw {
		t.Errorf("MessageType = %q", f.in.MessageType)
	}
	if f.in.SigningAlgorithm != types.SigningAlgorithmSpecRsassaPkcs1V15Sha256 {
		t.Errorf("SigningAlgorithm = %q", f.in.SigningAlgorithm)
	}

	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("jwt has %d parts", len(parts))
	}
	if signed := parts[0] + "." + parts[1]; string(f.in.Message) != signed {
		t.Errorf("signed message %q != jwt signing input %q", f.in.Message, signed)
	}

	enc := base64.RawURLEncoding
	header, err := enc.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var h map[string]string
	if err := json.Unmarshal(header, &h); err != nil {
		t.Fatal(err)
	}
	if h["alg"] != "RS256" || h["typ"] != "JWT" {
		t.Errorf("header = %v", h)
	}

	payload, err := enc.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		IAT int64  `json:"iat"`
		EXP int64  `json:"exp"`
		ISS string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		t.Fatal(err)
	}
	if c.ISS != "Iv1.abc" {
		t.Errorf("iss = %q", c.ISS)
	}
	after := time.Now().Unix()
	if c.IAT < before-60 || c.IAT > after-60 {
		t.Errorf("iat = %d, want now-60 (%d..%d)", c.IAT, before-60, after-60)
	}
	if c.EXP-c.IAT != 600 {
		t.Errorf("exp-iat = %d, want 600", c.EXP-c.IAT)
	}
	if c.EXP-after > 9*60 || c.EXP <= after {
		t.Errorf("exp = %d not within 9m of now", c.EXP)
	}

	sig, err := enc.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&testKey().PublicKey, crypto.SHA256, sum[:], sig); err != nil {
		t.Errorf("signature does not verify: %v", err)
	}
}

// newTestServer returns the production client, trusting only the test server's certificate.
func newTestServer(t *testing.T, h http.HandlerFunc) (string, *http.Client) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	c := *httpClient
	c.Transport = srv.Client().Transport
	return srv.URL, &c
}

func mintAgainst(t *testing.T, h http.HandlerFunc, s signer) (*installationToken, error) {
	t.Helper()
	srvURL, client := newTestServer(t, h)
	return mint(t.Context(), client, s, testSettings(t, srvURL, defaultBody))
}

func testSettings(t *testing.T, apiURL string, body string) *settings {
	t.Helper()
	u, err := url.Parse(apiURL)
	if err != nil {
		t.Fatal(err)
	}
	return &settings{appID: "123", installationID: 42, keyID: "k", api: u, body: []byte(body)}
}

func TestMintRequest(t *testing.T) {
	tests := []struct {
		name     string
		apiPath  string
		body     string
		wantPath string
	}{
		{"default body", "", defaultBody, "/app/installations/42/access_tokens"},
		{"custom body", "", `{"repositories":["r"]}`, "/app/installations/42/access_tokens"},
		{"ghes base path", "/api/v3", defaultBody, "/api/v3/app/installations/42/access_tokens"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got *http.Request
			var gotBody []byte
			srvURL, client := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				got = r
				gotBody, _ = io.ReadAll(r.Body)
				w.WriteHeader(http.StatusCreated)
				_, _ = io.WriteString(w, `{"token":"ghs_x","expires_at":"2030-01-02T03:04:05Z"}`)
			})

			f := &fakeSigner{}
			tok, err := mint(t.Context(), client, f, testSettings(t, srvURL+tt.apiPath, tt.body))
			if err != nil {
				t.Fatal(err)
			}
			if tok.Token != "ghs_x" || !tok.ExpiresAt.Equal(time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)) {
				t.Errorf("tok = %+v", tok)
			}

			if got.Method != http.MethodPost {
				t.Errorf("method = %s", got.Method)
			}
			if got.URL.Path != tt.wantPath {
				t.Errorf("path = %s, want %s", got.URL.Path, tt.wantPath)
			}
			auth, ok := strings.CutPrefix(got.Header.Get("Authorization"), "Bearer ")
			if !ok || strings.Count(auth, ".") != 2 || !strings.HasPrefix(auth, string(f.in.Message)) {
				t.Errorf("Authorization = %q", got.Header.Get("Authorization"))
			}
			if v := got.Header.Get("Accept"); v != "application/vnd.github+json" {
				t.Errorf("Accept = %q", v)
			}
			if v := got.Header.Get("X-GitHub-Api-Version"); v != "2022-11-28" {
				t.Errorf("X-GitHub-Api-Version = %q", v)
			}
			if string(gotBody) != tt.body {
				t.Errorf("body = %q, want %q", gotBody, tt.body)
			}
			if v := got.Header.Get("Content-Type"); v != "application/json" {
				t.Errorf("Content-Type = %q", v)
			}
		})
	}
}

func TestMintErrors(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		body    string
		wantErr string
	}{
		{"unauthorized", http.StatusUnauthorized, `{"message":"Bad credentials"}`, `401 Unauthorized: "{\"message\":\"Bad credentials\"}"`},
		{"ok is not created", http.StatusOK, `{"token":"ghs_x"}`, "200 OK"},
		{"empty token", http.StatusCreated, `{"token":""}`, "contained no token"},
		{"missing token", http.StatusCreated, `{}`, "contained no token"},
		{"newline in token", http.StatusCreated, `{"token":"ghs_x\nhost=evil"}`, "control characters"},
		{"nul in token", http.StatusCreated, `{"token":"ghs_x\u0000"}`, "control characters"},
		{"invalid json", http.StatusCreated, `nope`, "decode token response"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := mintAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = io.WriteString(w, tt.body)
			}, &fakeSigner{})
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("err = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestMintErrorBodyTruncated(t *testing.T) {
	_, err := mintAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, strings.Repeat("a", 10<<10))
	}, &fakeSigner{})
	if err == nil || len(err.Error()) > 5<<10 {
		t.Errorf("error body not truncated: len %d", len(err.Error()))
	}
}

func TestMintDoesNotFollowRedirect(t *testing.T) {
	var followed bool
	_, err := mintAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/elsewhere" {
			followed = true
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"token":"stolen"}`)
			return
		}
		http.Redirect(w, r, "/elsewhere", http.StatusTemporaryRedirect)
	}, &fakeSigner{})
	if err == nil || !strings.Contains(err.Error(), "307") {
		t.Errorf("err = %v, want 307 error", err)
	}
	if followed {
		t.Error("redirect was followed")
	}
}

func TestMintSignError(t *testing.T) {
	var called bool
	_, err := mintAgainst(t, func(http.ResponseWriter, *http.Request) { called = true }, &fakeSigner{err: errors.New("denied")})
	if err == nil || !strings.Contains(err.Error(), "kms sign: denied") {
		t.Errorf("err = %v", err)
	}
	if called {
		t.Error("API called despite signing failure")
	}
}

func TestWriteCredential(t *testing.T) {
	tests := []struct {
		name string
		tok  installationToken
		want string
	}{
		{
			name: "with expiry",
			tok:  installationToken{Token: "ghs_x", ExpiresAt: time.Unix(1893553445, 0)},
			want: "username=x-access-token\npassword=ghs_x\npassword_expiry_utc=1893553145\n",
		},
		{
			name: "without expiry",
			tok:  installationToken{Token: "ghs_x"},
			want: "username=x-access-token\npassword=ghs_x\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := writeCredential(&buf, &tt.tok); err != nil {
				t.Fatal(err)
			}
			if buf.String() != tt.want {
				t.Errorf("got %q, want %q", buf.String(), tt.want)
			}
		})
	}
}

func TestRunIgnores(t *testing.T) {
	const github = "protocol=https\nhost=github.com\n\n"
	tests := []struct {
		name  string
		args  []string
		host  string
		stdin string
	}{
		{name: "no args", stdin: github},
		{name: "store", args: []string{"store"}, stdin: github},
		{name: "erase", args: []string{"erase"}, stdin: github},
		{name: "extra args", args: []string{"get", "x"}, stdin: github},
		{name: "http protocol", args: []string{"get"}, stdin: "protocol=http\nhost=github.com\n"},
		{name: "other host", args: []string{"get"}, stdin: "protocol=https\nhost=gitlab.com\n"},
		{name: "host with port", args: []string{"get"}, stdin: "protocol=https\nhost=github.com:443\n"},
		{name: "default host when GH_HOST set", args: []string{"get"}, host: "ghe.example.com", stdin: github},
		{name: "host after blank line", args: []string{"get"}, stdin: "protocol=https\n\nhost=github.com\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setValidEnv(t)
			t.Setenv("GH_HOST", tt.host)
			var out bytes.Buffer
			if err := run(tt.args, strings.NewReader(tt.stdin), &out); err != nil {
				t.Fatalf("err = %v", err)
			}
			if out.Len() != 0 {
				t.Errorf("unexpected output %q", out.String())
			}
		})
	}
}

func TestRunVersion(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"--version"}, strings.NewReader(""), &out); err != nil {
		t.Fatalf("err = %v", err)
	}
	if got := out.String(); got != "dev\n" {
		t.Errorf("output = %q, want %q", got, "dev\n")
	}
}

func TestRunMatchingHostValidatesConfig(t *testing.T) {
	tests := []struct {
		name  string
		host  string
		stdin string
	}{
		{"default host", "", "protocol=https\nhost=github.com\n"},
		{"host is case-insensitive", "", "protocol=https\nhost=GitHub.com\n"},
		{"custom host", "ghe.example.com", "protocol=https\nhost=ghe.example.com\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setValidEnv(t)
			t.Setenv("GH_HOST", tt.host)
			t.Setenv("GH_APP_ID", "")
			var out bytes.Buffer
			err := run([]string{"get"}, strings.NewReader(tt.stdin), &out)
			if err == nil || !strings.Contains(err.Error(), "GH_APP_ID is required") {
				t.Errorf("err = %v", err)
			}
			if out.Len() != 0 {
				t.Errorf("unexpected output %q", out.String())
			}
		})
	}
}
