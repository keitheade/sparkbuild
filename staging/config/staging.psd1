@{
    # ------------------------------------------------------------------
    # SPARKSOC staging configuration — Windows 11 x86_64 staging host
    # Edit pins here. Everything downstream reads from this file.
    # ------------------------------------------------------------------

    BundleVersion = '1.0.0'

    # Where large intermediates are built. Needs ~400 GB free.
    WorkRoot      = 'D:\sparksoc-staging'

    # USB target. MUST be exFAT or NTFS — FAT32 cannot hold >4 GB files.
    # Bundles are split at 3.8 GB regardless, for resumable transfer.
    UsbRoot       = 'E:\sparksoc'

    TargetPlatform = 'linux/arm64'

    # ------------------------------------------------------------------
    # Models — Hugging Face repo IDs
    # ------------------------------------------------------------------
    Models = @(
        @{
            Name      = 'triage'
            RepoId    = 'Qwen/Qwen3.5-35B-A3B'
            LocalDir  = 'Qwen3.5-35B-A3B'
            Node      = 'spark1'
            ApproxGB  = 70
            # Exclude anything we will never load. Keeps USB size down.
            Exclude   = @('*.pth', '*.msgpack', '*.h5', 'original/*')
        },
        @{
            Name      = 'embed'
            RepoId    = 'Qwen/Qwen3-Embedding-0.6B'
            LocalDir  = 'Qwen3-Embedding-0.6B'
            Node      = 'spark1'
            ApproxGB  = 2
            Exclude   = @('*.pth', '*.msgpack', '*.h5', 'onnx/*', '*.gguf')
        },
        @{
            Name      = 'reason'
            RepoId    = 'openai/gpt-oss-120b'
            LocalDir  = 'gpt-oss-120b'
            Node      = 'spark2'
            ApproxGB  = 65
            Exclude   = @('*.pth', '*.msgpack', '*.h5', 'metal/*', 'original/*')
        }
    )

    # ------------------------------------------------------------------
    # Container images. Pulled for TargetPlatform, digest-pinned at
    # staging time into MANIFEST.json.
    # ------------------------------------------------------------------
    Images = @(
        @{ Ref = 'vllm/vllm-openai:cu130-nightly'; Alias = 'vllm';    Critical = $true  },
        @{ Ref = 'qdrant/qdrant:v1.12.4';          Alias = 'qdrant';  Critical = $true  },
        @{ Ref = 'python:3.11-slim';               Alias = 'python';  Critical = $true  },
        @{ Ref = 'redis:7.4-alpine';               Alias = 'redis';   Critical = $true  }
    )

    # ------------------------------------------------------------------
    # MITRE ATT&CK Enterprise STIX 2.1
    # Pin the version. 'latest' is not reproducible and this is an enclave.
    # Browse tags: https://github.com/mitre-attack/attack-stix-data
    # ------------------------------------------------------------------
    Attack = @{
        Version = 'v17.1'
        Url     = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-17.1.json'
        FileName = 'enterprise-attack.json'
        # Optional: also stage ICS / Mobile matrices for range coverage
        Extra   = @()
    }

    # ------------------------------------------------------------------
    # Offline Python wheelhouse. Built INSIDE an arm64 container under
    # qemu, not with `pip download --platform`, because sdist-only
    # packages must actually compile for aarch64.
    # ------------------------------------------------------------------
    Wheelhouse = @{
        PythonImage = 'python:3.11-slim'
        # Requirements files relative to the repo root
        Sources = @(
            'spark1/requirements.txt',
            'harness/requirements.txt',
            'validate/requirements.txt'
        )
    }

    # ------------------------------------------------------------------
    # Smoke gate. Test-SparkSmoke.ps1 must pass before bundling.
    # Set SkipSmokeGate only if you accept deploying an unverified runtime.
    # ------------------------------------------------------------------
    SmokeGate = @{
        Enabled = $true
        # A reachable DGX Spark used ONLY during staging, before airgapping.
        # If you have no such host, set Enabled=$false and accept the risk
        # documented in docs/01-STAGING.md section 7.
        SparkHost = 'spark1.staging.local'
        SparkUser = 'nvidia'
        SshKey    = '~\.ssh\id_ed25519_spark'
    }

    SplitSizeBytes = 4079218688   # 3.8 GiB
}
