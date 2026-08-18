# TLS certificates

## soar-ca.pem — required before first start

`docker-compose.yaml` bind-mounts this file into the harness container. **If the
file does not exist, Docker creates a directory with that name instead**, and the
harness then fails TLS verification against SOAR with a confusing error about the
CA bundle. Create it before `docker compose up`:

    openssl s_client -connect soar.range.local:443 -showcerts </dev/null 2>/dev/null \
      | openssl x509 -outform PEM > soar-ca.pem

Or copy the CA your organisation issued the SOAR certificate from — preferable,
since the command above pins the leaf rather than the issuer.

## If SOAR is reached over plain HTTP

Set `SOAR_CA_HOST_PATH=/dev/null` in `.env` and `SOAR_CA_BUNDLE=false`. The
harness logs a warning on every start when TLS verification is disabled, which is
intentional — this should be visible, not quiet.
