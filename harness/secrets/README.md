# Harness secrets

One secret per file, no trailing newline, mode 0400, owned by the user running
Docker. These are mounted as Docker secrets at `/run/secrets/<name>` and read by
`config.py` through the `*_FILE` environment variables.

    spark1_api_key       must equal VLLM_API_KEY in spark1/.env
    spark2_api_key       must equal VLLM_API_KEY in spark2/.env
    qdrant_api_key       must equal QDRANT_API_KEY in spark1/.env
    soar_token           Splunk SOAR automation user's ph-auth-token
    splunk_hmac_secret   must equal the shared secret in TA-soc-harness

Generate:

    for f in spark1_api_key spark2_api_key qdrant_api_key splunk_hmac_secret; do
      openssl rand -hex 32 | tr -d '\n' > "$f"
    done
    printf '%s' 'PASTE_SOAR_TOKEN_HERE' > soar_token
    chmod 400 *
    # Do not commit this directory.

The SOAR token comes from SOAR > Administration > User Management > Users >
(your automation user) > REST API key. See docs/06-SOAR-INTEGRATION.md.
