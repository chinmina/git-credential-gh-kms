// git-credential-gh-kms is a git credential helper that mints a
// GitHub App installation token, signing the App JWT with an AWS KMS key.
//
// Env:
//
//	GH_APP_ID           GitHub App ID or Client ID (JWT "iss")
//	GH_INSTALLATION_ID  installation to mint a token for (positive integer)
//	GH_KMS_KEY_ID       KMS key ID, ARN or alias (RSA_2048, SIGN_VERIFY)
//	GH_HOST             optional, git host to answer for (default github.com)
//	GH_API_URL          optional, API base (default https://api.github.com,
//	                    or https://<GH_HOST>/api/v3 for GHES)
//	GH_TOKEN_REQUEST    optional, JSON object body for the token request
//	                    (default {"permissions":{"contents":"read"}})
package main

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

const (
	defaultHost = "github.com"
	defaultAPI  = "https://api.github.com"
	jwtHeader   = `{"alg":"RS256","typ":"JWT"}`
	defaultBody = `{"permissions":{"contents":"read"}}`
	// Report expiry early so git's cache never hands out a token that lapses mid-fetch.
	expiryMargin = 5 * time.Minute
	timeout      = 30 * time.Second
)

// Set at release build time by goreleaser.
var version = "dev"

var httpClient = &http.Client{
	// Never replay a bearer-authenticated POST to a redirect target.
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

type settings struct {
	appID          string
	installationID uint64
	keyID          string
	api            *url.URL
	body           jsontext.Value
}

type signer interface {
	Sign(context.Context, *kms.SignInput, ...func(*kms.Options)) (*kms.SignOutput, error)
}

type installationToken struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "git-credential-gh-kms:", err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) == 1 && args[0] == "--version" {
		_, err := fmt.Fprintln(stdout, version)
		return err
	}
	// Only "get" is meaningful; store/erase are no-ops (caching is git's job).
	if len(args) != 1 || args[0] != "get" {
		return nil
	}
	req, err := readRequest(stdin)
	if err != nil {
		return fmt.Errorf("read credential request: %w", err)
	}
	host := cmp.Or(os.Getenv("GH_HOST"), defaultHost)
	if req["protocol"] != "https" || !asciiEqualFold(req["host"], host) {
		return nil // not ours; let git try the next helper
	}

	s, err := load(host)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("aws config: %w", err)
	}
	tok, err := mint(ctx, httpClient, kms.NewFromConfig(cfg), s)
	if err != nil {
		return err
	}
	return writeCredential(stdout, tok)
}

// asciiEqualFold matches DNS names case-insensitively. strings.EqualFold also
// folds Unicode, so "ſ" (U+017F) would match "s" and "K" (U+212A) "k".
func asciiEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range len(a) {
		if asciiLower(a[i]) != asciiLower(b[i]) {
			return false
		}
	}
	return true
}

func asciiLower(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

func writeCredential(stdout io.Writer, tok *installationToken) error {
	b := fmt.Appendf(nil, "username=x-access-token\npassword=%s\n", tok.Token)
	if !tok.ExpiresAt.IsZero() {
		// Git >= 2.41 honours this, so cached tokens are dropped on expiry.
		b = fmt.Appendf(b, "password_expiry_utc=%d\n", tok.ExpiresAt.Add(-expiryMargin).Unix())
	}
	_, err := stdout.Write(b)
	return err
}

// readRequest parses git's key=value credential request up to the blank line.
func readRequest(r io.Reader) (map[string]string, error) {
	m := make(map[string]string)
	sc := bufio.NewScanner(r)
	for sc.Scan() && sc.Text() != "" {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		// Git sends single-valued attributes once; a repeat means injected lines.
		if _, dup := m[k]; dup && !strings.HasSuffix(k, "[]") {
			return nil, fmt.Errorf("duplicate attribute %q", k)
		}
		m[k] = v
	}
	return m, sc.Err()
}

func load(host string) (*settings, error) {
	var errs []error
	required := func(k string) string {
		v := os.Getenv(k)
		if v == "" {
			errs = append(errs, fmt.Errorf("%s is required", k))
		}
		return v
	}

	s := &settings{
		appID: required("GH_APP_ID"),
		keyID: required("GH_KMS_KEY_ID"),
	}

	if v := required("GH_INSTALLATION_ID"); v != "" {
		id, err := strconv.ParseUint(v, 10, 64)
		if err != nil || id == 0 {
			errs = append(errs, fmt.Errorf("GH_INSTALLATION_ID: %q is not a positive integer", v))
		}
		s.installationID = id
	}

	apiURL := defaultAPI
	if !asciiEqualFold(host, defaultHost) {
		apiURL = "https://" + host + "/api/v3"
	}
	api, err := url.Parse(cmp.Or(os.Getenv("GH_API_URL"), apiURL))
	switch {
	case err != nil:
		errs = append(errs, fmt.Errorf("GH_API_URL: %w", err))
	case api.Scheme != "https" || api.Host == "" || api.User != nil || api.RawQuery != "" || api.Fragment != "":
		errs = append(errs, errors.New("GH_API_URL must be an absolute https URL without userinfo, query or fragment"))
	}
	s.api = api

	s.body = jsontext.Value(cmp.Or(os.Getenv("GH_TOKEN_REQUEST"), defaultBody))
	if !s.body.IsValid() || s.body.Kind() != '{' {
		errs = append(errs, errors.New("GH_TOKEN_REQUEST must be a valid JSON object"))
	}

	return s, errors.Join(errs...)
}

func mint(ctx context.Context, client *http.Client, kmsClient signer, s *settings) (*installationToken, error) {
	jwt, err := signJWT(ctx, kmsClient, s.appID, s.keyID)
	if err != nil {
		return nil, err
	}

	endpoint := s.api.JoinPath("app", "installations", strconv.FormatUint(s.installationID, 10), "access_tokens")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(s.body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return nil, fmt.Errorf("POST %s: %s: %q", endpoint.Redacted(), resp.Status, bytes.TrimSpace(msg))
	}

	var tok installationToken
	if err := json.UnmarshalRead(io.LimitReader(resp.Body, 1<<20), &tok); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}
	if tok.Token == "" {
		return nil, errors.New("token response contained no token")
	}
	// A newline would let the response inject extra attributes into git's credential stream.
	if strings.ContainsAny(tok.Token, "\r\n\x00") {
		return nil, errors.New("token response contained control characters")
	}
	return &tok, nil
}

func signJWT(ctx context.Context, kmsClient signer, appID, keyID string) (string, error) {
	now := time.Now()
	claims, err := json.Marshal(struct {
		IssuedAt  int64  `json:"iat"`
		ExpiresAt int64  `json:"exp"`
		Issuer    string `json:"iss"`
	}{
		IssuedAt:  now.Add(-time.Minute).Unix(),    // allow for clock skew
		ExpiresAt: now.Add(9 * time.Minute).Unix(), // GitHub caps at 10m
		Issuer:    appID,
	})
	if err != nil {
		return "", err
	}

	enc := base64.RawURLEncoding
	buf := enc.AppendEncode(nil, []byte(jwtHeader))
	buf = append(buf, '.')
	buf = enc.AppendEncode(buf, claims)

	res, err := kmsClient.Sign(ctx, &kms.SignInput{
		KeyId:            aws.String(keyID),
		Message:          buf,
		MessageType:      types.MessageTypeRaw,
		SigningAlgorithm: types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
	})
	if err != nil {
		return "", fmt.Errorf("kms sign: %w", err)
	}

	buf = append(buf, '.')
	buf = enc.AppendEncode(buf, res.Signature)
	return string(buf), nil
}
