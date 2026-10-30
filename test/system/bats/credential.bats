# Black-box system test for git-credential-gh-kms.
#
# The BATS container runs the helper and the unshipped kms-support binary
# mounted from bin/linux/. The helper signs with Local KMS through the real AWS
# SDK, and kms-support serves a fake GitHub token endpoint that only accepts
# JWTs verifying against that KMS key's public key.

bats_require_minimum_version 1.5.0

setup_file() {
  KMS_SUPPORT=/artifacts/kms-support
  HELPER=/artifacts/git-credential-gh-kms
  export KMS_SUPPORT HELPER

  AWS_ACCESS_KEY_ID=test
  AWS_SECRET_ACCESS_KEY=test
  AWS_REGION=us-east-1
  AWS_ENDPOINT_URL_KMS=http://kms:8080
  AWS_EC2_METADATA_DISABLED=true
  export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_REGION AWS_ENDPOINT_URL_KMS AWS_EC2_METADATA_DISABLED

  KMS_KEY_ARN=$(create_key -arn -alias alias/github-app) || {
    echo "Local KMS did not become ready" >&3
    return 1
  }
  GH_KMS_KEY_ID=${KMS_KEY_ARN##*/}
  GH_APP_ID=123456
  GH_INSTALLATION_ID=42
  GH_API_URL=https://localhost:8443
  INSTALLATION_TOKEN=ghs_systemtest
  SSL_CERT_FILE=$BATS_FILE_TMPDIR/fake-github.pem
  export KMS_KEY_ARN GH_KMS_KEY_ID GH_APP_ID GH_INSTALLATION_ID GH_API_URL INSTALLATION_TOKEN SSL_CERT_FILE

  # fd 3 is closed so BATS does not wait on the background server.
  "$KMS_SUPPORT" fake-github \
    -listen 127.0.0.1:8443 \
    -key-id "$GH_KMS_KEY_ID" \
    -app-id "$GH_APP_ID" \
    -installation-id "$GH_INSTALLATION_ID" \
    -token "$INSTALLATION_TOKEN" \
    -ca-out "$SSL_CERT_FILE" \
    >"$BATS_FILE_TMPDIR/fake-github.log" 2>&1 3>&- &
  FAKE_GITHUB_PID=$!
  export FAKE_GITHUB_PID

  for _ in {1..30}; do
    [[ -s "$SSL_CERT_FILE" ]] && return 0
    kill -0 "$FAKE_GITHUB_PID" 2>/dev/null || break
    sleep 1
  done
  echo "fake GitHub did not start:" >&3
  cat "$BATS_FILE_TMPDIR/fake-github.log" >&3
  return 1
}

teardown_file() {
  kill "$FAKE_GITHUB_PID" 2>/dev/null || true
}

setup() {
  load /usr/lib/bats/bats-support/load.bash
  load /usr/lib/bats/bats-assert/load.bash
}

teardown() {
  if [[ -n "${BATS_TEST_COMPLETED:-}" ]]; then
    return
  fi
  echo "# fake GitHub log:"
  sed 's/^/#   /' "$BATS_FILE_TMPDIR/fake-github.log"
}

# create_key keeps calling kms-support create-key until Local KMS is ready,
# then prints the new key's identifier. Arguments pass through to create-key.
create_key() {
  local key_id=""
  for _ in {1..30}; do
    key_id=$("$KMS_SUPPORT" create-key "$@" 2>/dev/null)
    if [[ -n "$key_id" ]]; then
      printf "%s" "$key_id"
      return 0
    fi
    sleep 1
  done
  return 1
}

# credential_get sends the request git sends for an HTTPS fetch from the
# given host (default github.com).
credential_get() {
  printf 'protocol=https\nhost=%s\npath=chinmina/example.git\n\n' "${1:-github.com}" | "$HELPER" get
}

# BATS runs each command in a subshell, so the unset does not leak.
credential_get_without_aws_credentials() {
  unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
  AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null credential_get
}

@test "mints an installation token signed by the KMS key" {
  run --separate-stderr credential_get
  assert_success
  assert_line --index 0 "username=x-access-token"
  assert_line --index 1 "password=$INSTALLATION_TOKEN"
  assert_line --index 2 --regexp '^password_expiry_utc=[0-9]+$'
  [[ ${#lines[@]} -eq 3 ]]
}

@test "reports expiry ahead of the token's real expiry" {
  run --separate-stderr credential_get
  assert_success

  local expiry now
  expiry=${lines[2]#password_expiry_utc=}
  now=$(date -u +%s)
  # The fake issues tokens for an hour; the helper reports 5 minutes early.
  (( expiry > now + 3000 && expiry <= now + 3300 ))
}

@test "signs with a key alias" {
  GH_KMS_KEY_ID=alias/github-app run --separate-stderr credential_get
  assert_success
  assert_line --index 1 "password=$INSTALLATION_TOKEN"
}

@test "signs with a key ARN" {
  GH_KMS_KEY_ID=$KMS_KEY_ARN run --separate-stderr credential_get
  assert_success
  assert_line --index 1 "password=$INSTALLATION_TOKEN"
}

@test "requests a token with a custom permissions body" {
  GH_TOKEN_REQUEST='{"repositories":["example"],"permissions":{"contents":"read","metadata":"read"}}' \
    run --separate-stderr credential_get
  assert_success
  assert_line --index 1 "password=$INSTALLATION_TOKEN"
}

@test "fails when GitHub rejects a signature from another KMS key" {
  local other_key
  other_key=$("$KMS_SUPPORT" create-key)
  GH_KMS_KEY_ID=$other_key run --separate-stderr credential_get
  assert_failure
  assert_equal "$output" ""
  [[ "$stderr" == *"401 Unauthorized"* ]]
}

@test "fails when GitHub rejects the App ID" {
  GH_APP_ID=654321 run --separate-stderr credential_get
  assert_failure
  assert_equal "$output" ""
  [[ "$stderr" == *"401 Unauthorized"* ]]
}

@test "fails when the installation does not exist" {
  GH_INSTALLATION_ID=7 run --separate-stderr credential_get
  assert_failure
  assert_equal "$output" ""
  [[ "$stderr" == *"404 Not Found"* ]]
}

@test "fails when the KMS key does not exist" {
  GH_KMS_KEY_ID=00000000-0000-0000-0000-000000000000 run --separate-stderr credential_get
  assert_failure
  assert_equal "$output" ""
  [[ "$stderr" == *"kms sign"*"NotFoundException"* ]]
}

@test "fails when the KMS key is not a signing key" {
  local key_id
  key_id=$("$KMS_SUPPORT" create-key -encrypt)
  GH_KMS_KEY_ID=$key_id run --separate-stderr credential_get
  assert_failure
  assert_equal "$output" ""
  # AWS answers InvalidKeyUsageException; Local KMS answers UnsupportedOperationException.
  [[ "$stderr" == *"kms sign: operation error KMS: Sign"* ]]
}

@test "fails when no AWS credentials are available" {
  run --separate-stderr credential_get_without_aws_credentials
  assert_failure
  assert_equal "$output" ""
  [[ "$stderr" == *"kms sign"*"credentials"* ]]
}

@test "fails when KMS is unreachable" {
  AWS_ENDPOINT_URL_KMS=http://127.0.0.1:1 run --separate-stderr credential_get
  assert_failure
  assert_equal "$output" ""
  [[ "$stderr" == *"kms sign"*"connection refused"* ]]
}

@test "fails when the GitHub certificate is not trusted" {
  SSL_CERT_FILE=/dev/null run --separate-stderr credential_get
  assert_failure
  assert_equal "$output" ""
  [[ "$stderr" == *"certificate"* ]]
}

@test "answers nothing for another host" {
  run --separate-stderr credential_get gitlab.com
  assert_success
  assert_equal "$output" ""
}
