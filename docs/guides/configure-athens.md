# Configuring Athens

This guide builds an [Athens][athens] image that fetches private Go modules from GitHub with installation tokens minted by `git-credential-gh-kms`.

Athens runs the go command for each module it has not yet stored, and the go command runs git. Athens passes the go command only `PATH`, `HOME`, `GIT_SSH`, `GIT_SSH_COMMAND`, `GOROOT`, the proxy variables, and the entries in `ATHENS_GO_BINARY_ENV_VARS`. The helper's `GH_*` settings and the AWS credential variables must be added to that list, which an entrypoint script does at container start.

## Before you start

You need:

- A GitHub App installed on the organisation that owns the private modules, with the **Contents** repository permission set to **Read-only**.
- The App's private key as a PEM file.
- The IAM role Athens runs as: an ECS task role, an EKS Pod Identity or IRSA role, or an EC2 instance profile role.
- The AWS CLI, with permission to create and administer KMS keys and attach IAM policies.
- Docker with BuildKit.

Substitute these placeholders throughout:

| Placeholder | Meaning | Example |
| ----------- | ------- | ------- |
| `<APP_ID>` | GitHub App ID or Client ID | `123456` |
| `<INSTALLATION_ID>` | Installation ID, shown at the end of the installation's settings URL | `78901234` |
| `<ORG>` | GitHub organisation that owns the private modules | `chinmina` |
| `<KEY_ALIAS>` | KMS key alias | `alias/athens-github-app` |
| `<AWS_REGION>` | Region of the KMS key | `ap-southeast-2` |
| `<ATHENS_ROLE_NAME>` | Name of the IAM role Athens runs as | `athens-proxy` |
| `<ATHENS_ROLE_ARN>` | ARN of that role | `arn:aws:iam::123456789012:role/athens-proxy` |
| `<INSTANCE_ID>` | EC2 instance running the Athens container, for Docker on EC2 only | `i-0abc123def4567890` |
| `<IMAGE>` | Image reference to build and push | `123456789012.dkr.ecr.ap-southeast-2.amazonaws.com/athens:v0.20.0-gh-kms` |
| `<ATHENS_URL>` | Base URL of the deployed proxy | `https://athens.example.com` |
| `<PRIVATE_MODULE>` | A private module path in `<ORG>` | `github.com/chinmina/private-lib` |

## 1. Create the signing key

1. Follow [Protecting the GitHub private key][chinmina-kms] on docs.chinmina.dev to create the key, its alias, and its key policy, and to import the private key.

   Use `<KEY_ALIAS>` for the alias. In the key policy, match `<ATHENS_ROLE_ARN>` where the example matches `role/chinmina-service-*`. The guide imports the key with [`kms-import`][kms-import], outside your infrastructure tooling, so no plaintext copy lands in Terraform state.

2. **Destroy every local copy of the PEM file.**

3. Confirm the key is ready to sign.

   ```sh
   aws kms describe-key --key-id <KEY_ALIAS> --region <AWS_REGION> \
     --query 'KeyMetadata.[KeyState,KeySpec,KeyUsage]' --output text
   ```

   The output is `Enabled	RSA_2048	SIGN_VERIFY`.

## 2. Allow Athens to sign

1. Create `athens-sign-policy.json`:

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": "kms:Sign",
         "Resource": "*",
         "Condition": {
           "StringEquals": { "kms:RequestAlias": "<KEY_ALIAS>" }
         }
       }
     ]
   }
   ```

   The `kms:RequestAlias` condition only matches requests that name the alias, so `GH_KMS_KEY_ID` must be `<KEY_ALIAS>`. Repointing the alias then rotates the key without a configuration change.

2. Attach the policy to the Athens role.

   ```sh
   aws iam put-role-policy --role-name <ATHENS_ROLE_NAME> \
     --policy-name athens-github-app-sign --policy-document file://athens-sign-policy.json
   ```

3. Confirm the role's IAM policies allow the call.

   ```sh
   aws iam simulate-principal-policy --policy-source-arn <ATHENS_ROLE_ARN> \
     --action-names kms:Sign \
     --context-entries 'ContextKeyName=kms:RequestAlias,ContextKeyValues=<KEY_ALIAS>,ContextKeyType=string' \
     --query 'EvaluationResults[0].EvalDecision' --output text
   ```

   The output is `allowed`. The simulation does not evaluate the key policy: [step 7](#7-verify-the-deployment) checks both together.

## 3. Write the git configuration

1. Create `gitconfig` in an empty build directory:

   ```ini
   # gitconfig
   [credential "https://github.com"]
       helper =
       helper = cache --timeout=3300
       helper = gh-kms
       useHttpPath = false
   ```

   The image copies this file to `/root/.gitconfig`, because the Athens image runs as `root`. `helper =` clears helpers from `/etc/gitconfig`. The 3300 second cache timeout matches the token expiry the helper reports. See [Git configuration](../../README.md#git-configuration) for the reasoning.

2. Remove any other GitHub credential configuration from the Athens deployment:

   - a `github-app` helper set up from the Athens documentation
   - a `.gitconfig` mounted over `/root/.gitconfig`, which replaces this file
   - the `ATHENS_GITHUB_TOKEN` and `ATHENS_NETRC_PATH` variables

> [!WARNING]
> Athens writes `ATHENS_GITHUB_TOKEN` to `/root/.netrc`, and copies `ATHENS_NETRC_PATH` there. When GitHub answers 401, git's HTTP client retries with the `.netrc` entry before it asks any credential helper. A valid token there is used for every fetch, and `git-credential-gh-kms` is never called.

## 4. Write the entrypoint script

1. Create `athens-entrypoint.sh` in the build directory:

   ```sh
   #!/bin/sh
   # athens-entrypoint.sh: Athens gives `go`, and so git, only a fixed set of variables.
   set -eu

   env_vars="${ATHENS_GO_BINARY_ENV_VARS:-GOPROXY=direct}"
   for name in GH_APP_ID GH_INSTALLATION_ID GH_KMS_KEY_ID GH_TOKEN_REQUEST \
     AWS_REGION AWS_DEFAULT_REGION \
     AWS_CONTAINER_CREDENTIALS_RELATIVE_URI AWS_CONTAINER_CREDENTIALS_FULL_URI \
     AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE \
     AWS_ROLE_ARN AWS_WEB_IDENTITY_TOKEN_FILE \
     AWS_EC2_METADATA_SERVICE_ENDPOINT; do
     value="$(printenv "${name}" || true)"
     if [ -n "${value}" ]; then
       env_vars="${env_vars}; ${name}=${value}"
     fi
   done
   export ATHENS_GO_BINARY_ENV_VARS="${env_vars}"

   exec "$@"
   ```

   The script appends each variable that is set to `ATHENS_GO_BINARY_ENV_VARS`. Athens splits that list on `;`, so no forwarded value may contain one. The script forwards credential provider variables only, and never static access keys (see [step 6](#6-configure-the-container)).

> [!IMPORTANT]
> `ATHENS_GO_BINARY_ENV_VARS` replaces `GoBinaryEnvVars` from the Athens config file. The script starts from `GOPROXY=direct`, the default in the image's config file. Move any other values from `GoBinaryEnvVars` into `ATHENS_GO_BINARY_ENV_VARS` in the container environment.

## 5. Build the image

The build installs the helper with mise in a separate stage, and copies only the binary into the Athens image. mise checks the release asset's checksum and its GitHub artifact attestation before it installs the binary.

1. Create `Dockerfile` in the build directory:

   ```dockerfile
   # syntax=docker/dockerfile:1
   ARG MISE_VERSION=2026.10.24
   ARG ATHENS_VERSION=v0.20.0

   FROM jdxcode/mise:${MISE_VERSION}-debian AS helper
   ARG HELPER_VERSION=0.1.0
   RUN mise use -g "github:chinmina/git-credential-gh-kms@${HELPER_VERSION}" \
     && install -D -m 0755 "$(mise which git-credential-gh-kms)" /out/git-credential-gh-kms

   FROM gomods/athens:${ATHENS_VERSION}
   COPY --from=helper /out/git-credential-gh-kms /usr/local/bin/git-credential-gh-kms
   COPY gitconfig /root/.gitconfig
   COPY --chmod=0755 athens-entrypoint.sh /usr/local/bin/athens-entrypoint
   ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/athens-entrypoint"]
   CMD ["athens-proxy", "-config_file=/config/config.toml"]
   ```

   The release binary is statically linked, so the glibc build stage and the Alpine-based Athens image share it. Update the three version arguments to pin newer releases.

2. Build the image.

   ```sh
   docker build -t <IMAGE> .
   ```

3. Confirm the image holds the helper and the git configuration.

   ```sh
   docker run --rm --entrypoint git <IMAGE> config --get-all credential.https://github.com.helper
   ```

   The output is an empty line, then `cache --timeout=3300`, then `gh-kms`.

4. Push the image.

   ```sh
   docker push <IMAGE>
   ```

## 6. Configure the container

1. Set these variables in the Athens container definition:

   | Variable | Value |
   | -------- | ----- |
   | `GH_APP_ID` | `<APP_ID>` |
   | `GH_INSTALLATION_ID` | `<INSTALLATION_ID>` |
   | `GH_KMS_KEY_ID` | `<KEY_ALIAS>` |
   | `AWS_REGION` | `<AWS_REGION>` |
   | `ATHENS_GONOSUM_PATTERNS` | `github.com/<ORG>/*` |

   The public checksum database has no record of private modules. Athens passes `ATHENS_GONOSUM_PATTERNS` to the go command as `GONOSUMDB`, so it skips the lookup for matching paths.

2. Keep the image's entrypoint. **ECS only:** leave `entryPoint` unset in the task definition. **Kubernetes only:** leave `command` unset in the pod spec.

3. Give Athens the role through the platform's credential provider. The platform sets the variables, and the entrypoint script forwards them:

   | Platform | Role source | Variables the platform sets |
   | -------- | ----------- | --------------------------- |
   | ECS on Fargate or EC2 | Task role | `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` |
   | EKS Pod Identity | Pod Identity association | `AWS_CONTAINER_CREDENTIALS_FULL_URI`, `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE` |
   | EKS IRSA | Service account annotation | `AWS_ROLE_ARN`, `AWS_WEB_IDENTITY_TOKEN_FILE` |
   | Docker on EC2 | Instance profile | None. The SDK uses the instance metadata service. |

   **Docker on EC2 only:** set the instance metadata hop limit to 2, so a container on a bridge network can reach the metadata service.

   ```sh
   aws ec2 modify-instance-metadata-options --instance-id <INSTANCE_ID> \
     --http-put-response-hop-limit 2
   ```

> [!WARNING]
> Do not set `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, or `AWS_SESSION_TOKEN` for Athens. The entrypoint fixes `ATHENS_GO_BINARY_ENV_VARS` at startup, and session credentials expire within 12 hours while the server keeps running. Long-lived access keys put a standing secret back on the host. The providers above serve fresh credentials to every helper run.

## 7. Verify the deployment

1. In a shell in the running Athens container, list a private repository's `HEAD`.

   ```sh
   git ls-remote https://<PRIVATE_MODULE> HEAD
   ```

   The output is a commit SHA followed by `HEAD`. This checks the helper, the AWS credentials, the key policy, and the GitHub App. A shell has the full container environment, so it does not check the entrypoint script.

2. Request the module's latest version through Athens.

   ```sh
   curl -fsS "<ATHENS_URL>/<PRIVATE_MODULE>/@latest"
   ```

   The output is JSON with a `Version` field. A failure response carries the helper's error message: see [Troubleshooting](#troubleshooting).

## Troubleshooting

Athens returns the go command's error output in the response body and its logs. Errors from the helper start with `git-credential-gh-kms:`.

| Message | Cause |
| ------- | ----- |
| `GH_APP_ID is required` | The entrypoint script did not run, so the helper's settings did not reach git. Check the image and the platform's entrypoint override. |
| `kms sign: ... get credentials: failed to refresh cached credentials` | No AWS credential source reached the helper. Check the role setup in [step 6](#6-configure-the-container). |
| `kms sign: ... AccessDeniedException` | The IAM policy or key policy denies `kms:Sign` to the role, or `GH_KMS_KEY_ID` is not `<KEY_ALIAS>`. |
| `POST https://api.github.com/app/installations/...: 401` or `404` | `GH_APP_ID`, `GH_INSTALLATION_ID`, and the imported key do not belong to the same GitHub App installation. |
| `terminal prompts disabled`, with no `git-credential-gh-kms:` line | Git did not call the helper. Check `/root/.gitconfig` and the `.netrc` sources in [step 3](#3-write-the-git-configuration). |
| `verifying module: ... sum.golang.org/lookup` | `ATHENS_GONOSUM_PATTERNS` does not match the module path. |

The credential cache daemon keeps its socket in `/root/.cache/git/credential/`. With a read-only root filesystem, mount a writable volume there. Otherwise every fetch mints a new token.

[athens]: https://docs.gomods.io/
[chinmina-kms]: https://docs.chinmina.dev/guides/kms/
[kms-import]: https://github.com/chinmina/kms-import
