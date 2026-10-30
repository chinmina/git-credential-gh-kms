// Command kms-support prepares and serves the black-box system tests for
// git-credential-gh-kms. It is not built by GoReleaser or shipped.
//
//	kms-support create-key [-arn] [-alias name] [-encrypt]
//	kms-support fake-github -key-id id -app-id id -installation-id n -token t -ca-out path [-listen addr]
package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "kms-support:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: kms-support create-key|fake-github [flags]")
	}
	switch args[0] {
	case "create-key":
		return createKey(ctx, args[1:])
	case "fake-github":
		return fakeGitHub(ctx, args[1:])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func kmsClient(ctx context.Context) (*kms.Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws config: %w", err)
	}
	return kms.NewFromConfig(cfg), nil
}

// createKey makes an RSA_2048 SIGN_VERIFY key (or a symmetric key with
// -encrypt) and prints its key ID, or its ARN with -arn.
func createKey(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("create-key", flag.ContinueOnError)
	wantARN := fs.Bool("arn", false, "print the key ARN instead of the key ID")
	alias := fs.String("alias", "", "also create this alias (alias/...) for the key")
	encrypt := fs.Bool("encrypt", false, "create a SYMMETRIC_DEFAULT ENCRYPT_DECRYPT key")
	if err := fs.Parse(args); err != nil {
		return err
	}

	client, err := kmsClient(ctx)
	if err != nil {
		return err
	}

	in := &kms.CreateKeyInput{KeySpec: types.KeySpecRsa2048, KeyUsage: types.KeyUsageTypeSignVerify}
	if *encrypt {
		in = &kms.CreateKeyInput{KeySpec: types.KeySpecSymmetricDefault, KeyUsage: types.KeyUsageTypeEncryptDecrypt}
	}
	out, err := client.CreateKey(ctx, in)
	if err != nil {
		return fmt.Errorf("create key: %w", err)
	}
	keyID := aws.ToString(out.KeyMetadata.KeyId)

	if *alias != "" {
		if _, err := client.CreateAlias(ctx, &kms.CreateAliasInput{AliasName: alias, TargetKeyId: &keyID}); err != nil {
			return fmt.Errorf("create alias: %w", err)
		}
	}

	if *wantARN {
		_, err = fmt.Println(aws.ToString(out.KeyMetadata.Arn))
	} else {
		_, err = fmt.Println(keyID)
	}
	return err
}

// fakeGitHub serves the installation access token endpoint over TLS, accepting
// only App JWTs that verify against the public half of a KMS key.
func fakeGitHub(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("fake-github", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:8443", "address to serve HTTPS on")
	keyID := fs.String("key-id", "", "KMS key whose public key verifies the App JWT")
	appID := fs.String("app-id", "", "expected JWT issuer")
	installationID := fs.String("installation-id", "", "the only installation that exists")
	token := fs.String("token", "", "installation token to issue")
	caOut := fs.String("ca-out", "", "path to write the server certificate PEM to once listening")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyID == "" || *appID == "" || *installationID == "" || *token == "" || *caOut == "" {
		return errors.New("fake-github: -key-id, -app-id, -installation-id, -token and -ca-out are required")
	}

	client, err := kmsClient(ctx)
	if err != nil {
		return err
	}
	pubOut, err := client.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: keyID})
	if err != nil {
		return fmt.Errorf("get public key: %w", err)
	}
	parsed, err := x509.ParsePKIXPublicKey(pubOut.PublicKey)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key is %T, want RSA", parsed)
	}

	cert, certPEM, err := selfSignedCert()
	if err != nil {
		return err
	}

	ln, err := new(net.ListenConfig).Listen(ctx, "tcp", *listen)
	if err != nil {
		return err
	}
	// Written only after Listen, so the file's existence signals readiness.
	if err := writeAtomic(*caOut, certPEM); err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /app/installations/{id}/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		if err := verifyAppJWT(r.Header.Get("Authorization"), pub, *appID, time.Now()); err != nil {
			log.Printf("installation %q: 401: %q", r.PathValue("id"), err.Error())
			writeJSON(w, http.StatusUnauthorized, map[string]string{"message": "A JSON web token could not be decoded"})
			return
		}
		if r.PathValue("id") != *installationID {
			log.Printf("installation %q: 404", r.PathValue("id"))
			writeJSON(w, http.StatusNotFound, map[string]string{"message": "Not Found"})
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil || jsontext.Value(body).Kind() != '{' || !jsontext.Value(body).IsValid() {
			log.Printf("installation %q: 422: body %q", r.PathValue("id"), body)
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"message": "Invalid request"})
			return
		}
		log.Printf("installation %q: 201", r.PathValue("id"))
		writeJSON(w, http.StatusCreated, map[string]any{
			"token":      *token,
			"expires_at": time.Now().Add(time.Hour).UTC().Truncate(time.Second),
		})
	})

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
	}
	log.Printf("listening on %s", ln.Addr())
	return srv.ServeTLS(ln, "", "")
}

// verifyAppJWT applies the checks GitHub makes on an App JWT: RS256, a valid
// signature, the expected issuer, and an expiry no more than 10 minutes out.
func verifyAppJWT(authz string, pub *rsa.PublicKey, appID string, now time.Time) error {
	jwt, ok := strings.CutPrefix(authz, "Bearer ")
	if !ok {
		return errors.New("no bearer token")
	}
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return errors.New("not a JWT")
	}
	enc := base64.RawURLEncoding
	header, err := enc.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("header: %w", err)
	}
	payload, err := enc.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("payload: %w", err)
	}
	sig, err := enc.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("signature: %w", err)
	}

	var h struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(header, &h); err != nil {
		return fmt.Errorf("header: %w", err)
	}
	if h.Alg != "RS256" {
		return fmt.Errorf("alg %q, want RS256", h.Alg)
	}

	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
		return fmt.Errorf("signature: %w", err)
	}

	var c struct {
		IssuedAt  int64  `json:"iat"`
		ExpiresAt int64  `json:"exp"`
		Issuer    string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return fmt.Errorf("claims: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(c.Issuer), []byte(appID)) != 1 {
		return fmt.Errorf("iss %q, want %q", c.Issuer, appID)
	}
	iat, exp := time.Unix(c.IssuedAt, 0), time.Unix(c.ExpiresAt, 0)
	switch {
	case iat.After(now):
		return fmt.Errorf("iat %v is in the future", iat)
	case !exp.After(now):
		return fmt.Errorf("exp %v has passed", exp)
	case exp.After(now.Add(10 * time.Minute)):
		return fmt.Errorf("exp %v is more than 10 minutes out", exp)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.MarshalWrite(w, v); err != nil {
		log.Printf("write response: %v", err)
	}
}

func selfSignedCert() (tls.Certificate, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "fake-github"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, certPEM, nil
}

func writeAtomic(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".ca-*")
	if err != nil {
		return err
	}
	_, werr := tmp.Write(b)
	cerr := tmp.Close()
	if err := errors.Join(werr, cerr); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
