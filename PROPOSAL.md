# Pulling Encrypted Container Images in Confidential VMs Without Kata Runtime

This document explains the architecture and mechanisms for pulling encrypted container images in Confidential VMs (CVMs) without the Kata runtime. It covers the standard Kubernetes image pull process, how Confidential Containers (CoCo) handles encrypted images, and how to achieve attestation-gated decryption in a CVM using only the Attestation Agent.

> **Practical Implementation**: For step-by-step instructions on deploying this architecture on Azure TDX CVMs, see the companion [README.md](./README.md).

## Table of Contents

1. [Standard Kubernetes Image Pull Process](#1-standard-kubernetes-image-pull-process)
2. [CoCo Encrypted Image Pull Flow](#2-coco-encrypted-image-pull-flow)
3. [Pulling Encrypted Images Without Kata Runtime](#3-pulling-encrypted-images-without-kata-runtime)
4. [References](#4-references)

## 1. Standard Kubernetes Image Pull Process

### 1.1 Overview

When a Pod is scheduled to a node, Kubernetes must ensure the container images are available locally before containers can start. This process involves multiple components working together through well-defined interfaces.

### 1.2 Components Involved

| Component                             | Role                                                            |
|---------------------------------------|-----------------------------------------------------------------|
| **kubelet**                           | Node agent that manages Pod lifecycle [1]                       |
| **CRI (Container Runtime Interface)** | gRPC API between kubelet and container runtime [1]              |
| **containerd**                        | Industry-standard container runtime [2]                         |
| **Snapshotter**                       | Manages filesystem snapshots for container layers [3]           |
| **Content Store**                     | Content-addressable storage for image blobs [3]                 |
| **Registry**                          | Remote storage for container images (e.g., Docker Hub, GCR) [4] |

### 1.3 Pull Sequence

The Kubernetes Container Runtime Interface (CRI) defines the main gRPC protocol for communication between the kubelet and container runtime [1]. The `PullImage` RPC method handles image pulls through this interface [1].

```mermaid
---
config:
  look: neo
  theme: redux-dark-color
---
sequenceDiagram
    participant K as kubelet
    participant C as containerd
    participant S as snapshotter
    participant R as registry

    K->>C: PullImage (CRI gRPC) [1]
    C->>R: GET `/v2/<name>/manifests/<ref>` [4]
    R-->>C: Image manifest (layers, config)

    loop For each layer
        C->>R: GET `/v2/<name>/blobs/<digest>` [4]
        R-->>C: Layer blob (tar+gzip)
        C->>S: Prepare snapshot [3]
        C->>S: Unpack layer [3]
    end

    C-->>K: Image ready
```

### 1.4 Step-by-Step Process

#### Step 1: Pod Scheduling and Image Check

When the kubelet receives a Pod spec, it first checks if the required images are already present locally. If not, it initiates a pull via the CRI `PullImage` RPC [1].

#### Step 2: CRI PullImage Request

The kubelet calls the CRI `PullImage` RPC on containerd, providing the image reference and any registry credentials from `imagePullSecrets` [5]. The `imagePullSecrets` field references Kubernetes Secrets of type `kubernetes.io/dockerconfigjson` containing registry credentials [5].

#### Step 3: Manifest Resolution

containerd resolves the image reference to a specific manifest using the OCI (Open Container Initiative) Distribution Specification [4]:

1. **Tag resolution**: If using a tag (e.g., `nginx:latest`), query the registry's manifest endpoint `GET /v2/<name>/manifests/<reference>` [4]
2. **Manifest fetch**: Download the image manifest containing configuration and layer digests [4]

Example OCI Image Manifest:
```json
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "config": {
    "mediaType": "application/vnd.oci.image.config.v1+json",
    "digest": "sha256:abc123...",
    "size": 1234
  },
  "layers": [
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "digest": "sha256:def456...",
      "size": 52428800
    }
  ]
}
```

#### Step 4: Layer Download and Unpacking

For each layer, containerd downloads the blob via `GET /v2/<name>/blobs/<digest>` [4], verifies its digest, stores it in the content-addressable store [3], and unpacks it via the snapshotter [3].

### 1.5 Container Filesystem Structure

```mermaid
graph TB
    subgraph "Container Rootfs"
        W["Writable Layer (container)"]
        LN["Layer N (read-only)"]
        L2["Layer 2 (read-only)"]
        L1["Layer 1 (read-only)"]
        B["Base Layer (read-only)"]
    end
    
    W --> LN
    LN --> L2
    L2 --> L1
    L1 --> B
```

The snapshotter creates a chain of read-only snapshots for each layer, with a writable layer on top for container modifications [3]. containerd ships with several built-in snapshotters, with overlayfs as the default [3].

### 1.6 Content-Addressable Storage

containerd uses content-addressable storage where blobs are identified by their cryptographic digest [3]:

```
/var/lib/containerd/
├── io.containerd.content.v1.content/
│   └── blobs/sha256/
│       ├── abc123...  (config blob)
│       └── def456...  (layer blob)
└── io.containerd.snapshotter.v1.overlayfs/
    └── snapshots/
        ├── 1/  (base layer)
        └── 2/  (layer + writable)
```

### 1.7 Key Characteristics of Standard Pull

| Aspect | Standard Behavior |
|--------|-------------------|
| **Pull location** | Host (worker node) [1] |
| **Layer storage** | Host filesystem [3] |
| **Decryption** | Not applicable (plaintext images) |
| **Trust model** | Trust the host, cluster admins, registry |
| **Verification** | Digest verification only [3] |

## 2. CoCo Encrypted Image Pull Flow

### 2.1 Why Encrypted Images?

In standard Kubernetes, container images are pulled on the untrusted host and stored in plaintext on the host filesystem, accessible to anyone with host access. For confidential computing workloads, this is unacceptable since images may contain proprietary code, embedded secrets, or sensitive ML models.

Confidential Containers (CoCo) addresses this by [6]:
1. **Encrypting** container image layers
2. Pulling and decrypting images **inside the TEE**
3. Releasing decryption keys only after **remote attestation**

### 2.2 OCI Image Encryption

CoCo uses the OCI image encryption specification implemented by the `ocicrypt` library [7]. The ocicrypt library is the OCI image spec implementation of container image encryption [7], though the specification remains a proposed extension to OCI image-spec (PR #775) rather than a merged standard [8].

Each layer is encrypted independently using a symmetric key (Layer Encryption Key), which is then wrapped by a Key Encryption Key (KEK) [7].

```mermaid
flowchart TB
    subgraph Encryption["Layer Encryption Process"]
        OL["Original Layer (tar+gzip)"]
        LEK["LEK (Layer Encryption Key)"]
        AES["AES-256-CTR + HMAC-SHA256 [9]"]
        EL["Encrypted Layer"]
        WLEK["Wrapped LEK in annotations"]
    end
    
    OL --> AES
    LEK --> AES
    AES --> EL
    LEK --> WLEK
    
    subgraph Result["Encrypted Image"]
        EL
        WLEK
    end
```

The encrypted image manifest indicates encryption via media type [10]:

```json
{
  "layers": [
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip+encrypted",
      "digest": "sha256:encrypted-digest...",
      "annotations": {
        "org.opencontainers.image.enc.keys.provider.attestation-agent": "<wrapped-LEK>",
        "org.opencontainers.image.enc.pubopts": "<encryption-params>"
      }
    }
  ]
}
```

The annotation key follows the pattern `org.opencontainers.image.enc.keys.provider.<name>` where `<name>` is the keyprovider name [11].

### 2.3 Key Hierarchy

The **Key Broker Service (KBS)** is a remote service that securely stores encryption keys and releases them only after verifying TEE attestation evidence. It works with an Attestation Service to validate that the requesting environment is a genuine, unmodified TEE [12].

```mermaid
flowchart TB
    KEK["KEK (Key Encryption Key)<br/>Stored in KBS<br/>Released after attestation"]
    LEK["LEK (Layer Encryption Key)<br/>Unique per layer<br/>Stored wrapped in annotations [7]"]
    LC["Layer Content<br/>(encrypted with AES-256-CTR [9])"]
    
    KEK -->|"Wraps"| LEK
    LEK -->|"Encrypts"| LC
```

- **KEK (Key Encryption Key)**: Master key stored in the Key Broker Service (KBS), released only after successful TEE attestation [12]
- **LEK (Layer Encryption Key)**: Symmetric key unique to each layer, wrapped by the KEK and stored in image annotations [7]

### 2.4 CoCo Architecture

CoCo uses Kata Containers to run pods inside lightweight VMs (micro-VMs) backed by hardware TEEs [6]. Kata Containers is an existing open source project that encapsulates pods inside of VMs [6]. Runtime classes include `kata-qemu-snp` (AMD SEV-SNP), `kata-qemu-tdx` (Intel TDX), and `kata-qemu-sev` [13].

```mermaid
flowchart TB
    subgraph Host["Worker Node - Host"]
        K[kubelet]
        C[containerd]
        KS[kata-shim]
        NS[nydus-snapshotter]
        HV[Hypervisor<br/>QEMU or CLH]
    end

    subgraph TEE["Confidential VM - TEE"]
        KA[kata-agent]
        IR["image-rs"]
        CDH["CDH"]
        AA["Attestation Agent"]
    end

    subgraph External["External Services"]
        KBS["KBS + Attestation Service"]
        REG[Container Registry]
    end

    K --> C
    C --> KS
    C --> NS
    KS --> HV
    HV --> KA
    NS -.->|"Redirect pull"| KA

    KA --> IR
    IR --> CDH
    CDH --> AA

    IR -->|"Pull layers"| REG
    AA -->|"Attestation + Key Request"| KBS


```

**Host-side components:**
- **kata-shim**: The containerd shim v2 implementation for Kata Containers. It acts as a bridge between containerd and the hypervisor, translating CRI requests into VM operations and managing the lifecycle of the micro-VM [6].
- **nydus-snapshotter**: A containerd snapshotter plugin that intercepts image pull requests and redirects them to be handled inside the guest VM. This enables lazy-pulling and on-demand loading of container images directly into the TEE [17].

### 2.5 Guest Components

CoCo introduces several components that run **inside the TEE** [6]:

| Component                       | Role                                                          |
|---------------------------------|---------------------------------------------------------------|
| **kata-agent**                  | Manages container lifecycle inside the VM [6]                 |
| **image-rs**                    | Rust crate for pulling, decrypting, and unpacking images [14] |
| **CDH (Confidential Data Hub)** | Coordinates secret retrieval and key management [15]          |
| **AA (Attestation Agent)**      | Handles TEE attestation and KBS communication [16]            |
| **ocicrypt-rs**                 | Rust implementation of OCI encryption/decryption [7]          |

**Important**: `image-rs` is a **Rust crate (library)**, not a standalone binary. The design document states it is "a rustified and tailored version of containers/image, to provide a small, simple, secure, lightweight and high performance OCI container image management library" [14]. It is imported and used by `kata-agent` to perform image operations.

### 2.6 CoCo Image Pull Sequence

On the host, a snapshotter is used to pre-empt image pull and divert control flow to image-rs inside the guest [17].

```mermaid
sequenceDiagram
    participant K as kubelet
    participant C as containerd
    participant NS as nydus-snapshotter
    participant KA as kata-agent
    participant IR as image-rs
    participant CDH as CDH
    participant AA as AA
    participant KBS as KBS
    participant R as Registry

    K->>C: CreatePod
    C->>NS: Pull image
    NS->>KA: Redirect to guest

    KA->>IR: Pull encrypted image
    IR->>R: Download manifest + encrypted layers
    R-->>IR: Encrypted layers

    IR->>CDH: Request decryption key
    CDH->>AA: Get key from annotation

    AA->>KBS: POST /kbs/v0/auth
    KBS-->>AA: Challenge with nonce
    AA->>KBS: POST /kbs/v0/attest with TEE evidence

    Note over KBS: Verify attestation<br/>via Attestation Service

    KBS-->>AA: Attestation token JWT
    AA-->>CDH: Attestation token

    CDH->>KBS: GET /kbs/v0/resource/path
    KBS-->>CDH: KEK

    Note over CDH: Unwrap LEK using KEK

    CDH-->>IR: Unwrapped LEK

    Note over IR: Decrypt layers

    IR-->>KA: Image ready
    KA-->>NS: Ready
    NS-->>C: Ready
    C-->>K: Pod ready
```

### 2.7 Attestation Protocol (RCAR)

The Attestation Agent uses the **RCAR (Request-Challenge-Attestation-Response)** protocol to establish trust with the KBS [18]. The protocol uses a "simple, universal, and extensible" method for attestation [18].

```mermaid
sequenceDiagram
    participant CDH as CDH
    participant AA as Attestation Agent
    participant KBS as Key Broker Service
    participant AS as Attestation Service

    rect rgb(40, 40, 60)
    Note over AA,KBS: RCAR Protocol

    AA->>KBS: 1. POST /kbs/v0/auth (Request)
    KBS-->>AA: 2. Challenge with nonce

    Note over AA: Generate TEE quote<br/>including nonce

    AA->>KBS: 3. POST /kbs/v0/attest (Attestation)

    KBS->>AS: Verify evidence
    AS-->>KBS: Verification result

    KBS-->>AA: 4. Attestation token JWT (Response)

    end

    Note over AA,KBS: Resource Retrieval (post-attestation)

    AA-->>CDH: Return token to CDH
    CDH->>KBS: GET /kbs/v0/resource/path with Bearer token
    KBS-->>CDH: KEK
```

The RCAR protocol (steps 1-4) establishes trust and ends when the attestation token (JWT) is issued. Resource retrieval (fetching the KEK) is a separate step performed by CDH using the token obtained from RCAR.

The protocol ensures:
- **Freshness**: Nonce prevents replay attacks [18]
- **Binding**: TEE quote includes the ephemeral public key [18]
- **Verification**: KBS validates evidence via Attestation Service before releasing keys [12]

### 2.8 Key Differences: Standard vs CoCo

| Aspect               | Standard Kubernetes  | Confidential Containers     |
|----------------------|----------------------|-----------------------------|
| **Pull location**    | Host [1]             | Inside TEE (guest) [6]      |
| **Image storage**    | Host filesystem [3]  | Guest memory/filesystem [6] |
| **Layer format**     | Plaintext            | Encrypted [7]               |
| **Key retrieval**    | N/A                  | Attestation-gated [18]      |
| **Trust boundary**   | Host, cluster admins | Hardware TEE only [6]       |
| **Runtime**          | runc/crun            | kata-runtime (micro-VM) [6] |
| **Image visibility** | Visible to host      | Opaque to host [6]          |

---

## 3. Pulling Encrypted Images Without Kata Runtime

> **Demo Note**: The companion [README.md](./README.md) implements this architecture using `offline_fs_kbc` mode, which stores decryption keys locally and **bypasses remote attestation**. This simplifies deployment but provides **no security guarantees**. 

### 3.1 Motivation

While CoCo provides a complete solution for confidential containers, it requires Kata Containers runtime, a hypervisor, and complex deployment. In some scenarios, you may want to:

- Run Kubernetes **directly inside a CVM** (TDX VM or SEV-SNP VM)
- Use the **standard containerd runtime** (no nested virtualization)
- Still benefit from **attestation-gated encrypted image decryption**

This architecture is simpler but trades per-pod TEE isolation for operational simplicity.

### 3.2 Solution Architecture

The key insight is that the **Confidential Data Hub (CDH)** implements the **ocicrypt keyprovider protocol** as a gRPC service [15]. CDH coordinates with the **Attestation Agent (AA)** for attestation when retrieving keys. containerd's decryption mechanism calls CDH directly.

#### Production Architecture (with Remote Attestation)

```mermaid
flowchart TB
    subgraph CVM["Confidential VM - TDX or SEV-SNP"]
        subgraph K8s["Kubernetes"]
            KL[kubelet]
        end

        subgraph Runtime["Container Runtime"]
            CD[containerd]
            CTD["ctd-decoder<br/>stream processor"]
        end

        subgraph GuestComponents["Guest Components"]
            CDH["CDH<br/>keyprovider gRPC<br/>port 50000"]
            AA["AA<br/>attestation ttrpc<br/>unix socket"]
            TEE[TEE Evidence<br/>Generation]
        end
    end

    subgraph External["External Services"]
        KBS["KBS + Attestation Service"]
        REG[Container Registry]
    end

    KL -->|"CRI"| CD
    CD -->|"Encrypted layer"| CTD
    CTD -->|"gRPC UnWrapKey"| CDH
    CDH -->|"ttrpc Attestation request"| AA
    AA --> TEE

    CD -->|"Pull"| REG
    AA -->|"HTTPS Attestation"| KBS
    CDH -->|"via AA"| KBS
```

#### Demo Architecture (offline_fs_kbc - Mocked Attestation)

> **Warning**: The demo uses `offline_fs_kbc` mode which stores keys locally without remote attestation. This bypasses the security guarantees of confidential computing and is **NOT suitable for production**.

```mermaid
flowchart TB
    subgraph CVM["Confidential VM (TDX / SEV-SNP)"]
        subgraph K8s["Kubernetes"]
            KL[kubelet]
        end

        subgraph Runtime["Container Runtime"]
            CD[containerd]
            CTD["ctd-decoder<br/>stream processor"]
        end

        subgraph GuestComponents["Guest Components"]
            CDH["CDH - keyprovider gRPC<br/>port 50000<br/>offline_fs_kbc mode"]
            AA["AA - ttrpc unix socket<br/>not used in offline mode"]
            KEYS["Local Keys File<br/>/etc/aa-offline_fs_kbc-resources.json"]
        end
    end

    subgraph External["External Services"]
        REG[Container Registry]
        KBS["KBS + Attestation Service<br/>NOT CONTACTED"]
    end

    KL -->|"CRI"| CD
    CD -->|"Encrypted layer"| CTD
    CTD -->|"gRPC UnWrapKey"| CDH
    CDH -->|"Read key"| KEYS

    CD -->|"Pull"| REG

    CDH -.->|"SKIPPED"| AA
    AA -.->|"SKIPPED"| KBS

```

**Key Differences in Demo Mode:**
- CDH configured with `offline_fs_kbc` instead of `cc_kbc`
- Keys stored locally in `/etc/aa-offline_fs_kbc-resources.json` (base64 encoded)
- No remote attestation performed
- KBS is deployed but **not contacted** at runtime
- Attestation Agent runs but is **not used** for key retrieval

### 3.3 How It Works

#### ocicrypt Keyprovider Protocol

The `ocicrypt` library supports a **keyprovider protocol** that allows external services to handle key operations [11]. The configuration is read from the `OCICRYPT_KEYPROVIDER_CONFIG` environment variable [20]. When containerd encounters an encrypted layer:

##### Production Flow (cc_kbc with Remote Attestation)

```mermaid
sequenceDiagram
    participant CD as containerd
    participant CTD as ctd-decoder
    participant CDH as CDH
    participant AA as Attestation Agent
    participant KBS as KBS

    CD->>CTD: Decrypt layer via stream processor

    Note over CTD: Read OCICRYPT_KEYPROVIDER_CONFIG<br/>Find attestation-agent provider

    CTD->>CDH: gRPC UnWrapKey with annotation

    Note over CDH: Parse wrapped LEK<br/>Extract key ID

    CDH->>AA: ttrpc request for attestation token
    AA->>KBS: Attestation if needed
    KBS-->>AA: Token
    AA-->>CDH: Token

    CDH->>KBS: GET resource KEK with token
    KBS-->>CDH: Wrapped KEK

    Note over CDH: Unwrap LEK using KEK

    CDH-->>CTD: Plaintext LEK

    Note over CTD: Decrypt layer using AES-256-CTR

    CTD-->>CD: Decrypted layer
```

##### Demo Flow (offline_fs_kbc - No Attestation)

```mermaid
sequenceDiagram
    participant CD as containerd
    participant CTD as ctd-decoder
    participant CDH as CDH
    participant KEYS as Local Keys File

    CD->>CTD: Decrypt layer via stream processor

    Note over CTD: Read OCICRYPT_KEYPROVIDER_CONFIG<br/>Find attestation-agent provider

    CTD->>CDH: gRPC UnWrapKey with annotation

    Note over CDH: Parse annotation<br/>Extract key ID

    Note over CDH: offline_fs_kbc mode<br/>Read from local file instead of KBS

    CDH->>KEYS: Read aa-offline_fs_kbc-resources.json
    KEYS-->>CDH: Base64-encoded KEK

    Note over CDH: Unwrap LEK using KEK

    CDH-->>CTD: Plaintext LEK

    Note over CTD: Decrypt layer using AES-256-CTR

    CTD-->>CD: Decrypted layer

    Note over CD,KEYS: No attestation performed - No KBS contacted
```

#### CDH as Keyprovider

The Confidential Data Hub (CDH) exposes a gRPC service implementing the keyprovider protocol [15]. The service listens on port 50000 by default for the keyprovider interface:

```protobuf
service KeyProviderService {
    rpc UnWrapKey(keyProviderKeyWrapProtocolInput)
        returns (keyProviderKeyWrapProtocolOutput);
}
```

When CDH receives an `UnWrapKey` request [15], it:
1. Parses the annotation packet containing the wrapped LEK
2. Calls the Attestation Agent (AA) via ttrpc to get an attestation token
3. AA generates TEE evidence and exchanges it with KBS for a token [18]
4. CDH requests the KEK from KBS using the key ID and attestation token [18]
5. CDH unwraps the LEK using the KEK
6. Returns the plaintext LEK to the caller

**Note**: CDH coordinates the entire key retrieval flow, delegating only the attestation step to AA. This separation allows CDH to support multiple Key Broker Clients (KBCs) like `cc_kbc`, `offline_fs_kbc`, etc., each with different attestation and key retrieval strategies [15].

#### containerd Configuration

containerd supports encrypted image decryption through stream processors [10]. The `ctd-decoder` binary from the imgcrypt project handles decryption [10]. Configuration uses `key_model = "node"` where encryption is tied to worker nodes [21].

### 3.4 Components Required

| Component                     | Source                                          | Role                                        |
|-------------------------------|-------------------------------------------------|---------------------------------------------|
| **containerd**                | Standard distribution                           | Container runtime with CRI support [2]      |
| **ctd-decoder**               | `containerd/imgcrypt` [10]                      | Stream processor for encrypted layers       |
| **Confidential Data Hub**     | `confidential-containers/guest-components` [15] | Keyprovider service (gRPC port 50000)       |
| **Attestation Agent**         | `confidential-containers/guest-components` [16] | TEE attestation service (ttrpc unix socket) |
| **KBS + Attestation Service** | `confidential-containers/trustee` [12]          | External key broker and verifier            |

Both CDH and AA can be built with different attesters depending on the TEE platform: `tdx-attester`, `snp-attester`, `az-snp-vtpm-attester`, `az-tdx-vtpm-attester`, `sgx-attester`, `cca-attester`, and `se-attester` [19].

**Build Configuration:**
- CDH: Built with `grpc` and `kbs` features to expose keyprovider service
- AA: Built with `ttrpc` feature to communicate with CDH via unix socket

### 3.5 Image Pull Flow

#### Production Flow (cc_kbc with Remote Attestation)

```mermaid
sequenceDiagram
    participant K as kubelet
    participant C as containerd
    participant CTD as ctd-decoder
    participant CDH as CDH
    participant AA as AA
    participant KBS as KBS
    participant R as Registry

    K->>C: PullImage
    C->>R: Download manifest and encrypted layers
    R-->>C: Encrypted layers

    C->>CTD: Decrypt layer via stream processor
    CTD->>CDH: UnWrapKey gRPC port 50000

    CDH->>AA: Get attestation token via ttrpc
    AA->>KBS: Attestation flow
    KBS-->>AA: Attestation token
    AA-->>CDH: Token

    CDH->>KBS: GET resource with token
    KBS-->>CDH: KEK

    Note over CDH: Unwrap LEK using KEK

    CDH-->>CTD: LEK

    Note over CTD: Decrypt layer

    CTD-->>C: Decrypted layer

    Note over C: Unpack and snapshot

    C-->>K: Image ready
```

#### Demo Flow (offline_fs_kbc - No Attestation)

> **Note**: This is the flow used in [README.md](./README.md). Attestation is bypassed and keys are read from a local file.

```mermaid
sequenceDiagram
    participant K as kubelet
    participant C as containerd
    participant CTD as ctd-decoder
    participant CDH as CDH
    participant KEYS as Local Keys
    participant R as Registry

    K->>C: PullImage
    C->>R: Download manifest and encrypted layers
    R-->>C: Encrypted layers

    C->>CTD: Decrypt layer via stream processor
    CTD->>CDH: UnWrapKey gRPC port 50000

    Note over CDH: offline_fs_kbc mode

    CDH->>KEYS: Read aa-offline_fs_kbc-resources.json
    KEYS-->>CDH: KEK base64 decoded

    Note over CDH: Unwrap LEK using KEK

    CDH-->>CTD: LEK

    Note over CTD: Decrypt layer

    CTD-->>C: Decrypted layer

    Note over C: Unpack and snapshot

    C-->>K: Image ready

    Note over K,KEYS: Attestation SKIPPED - KBS NOT contacted
```


## 4. References

[1] Kubernetes Project, "Container Runtime Interface (CRI)," Kubernetes Documentation. Available: https://kubernetes.io/docs/concepts/architecture/cri/

[2] containerd Authors, "containerd: An industry-standard container runtime," GitHub. Available: https://github.com/containerd/containerd

[3] containerd Authors, "Content Flow," containerd Documentation. Available: https://github.com/containerd/containerd/blob/main/docs/content-flow.md

[4] Open Container Initiative, "OCI Distribution Specification," GitHub. Available: https://github.com/opencontainers/distribution-spec/blob/main/spec.md

[5] Kubernetes Project, "Pull an Image from a Private Registry," Kubernetes Documentation. Available: https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/

[6] Confidential Containers Project, "Design Overview," Confidential Containers Documentation. Available: https://confidentialcontainers.org/docs/architecture/design-overview/

[7] containers/ocicrypt Authors, "ocicrypt - OCI image encryption library," GitHub. Available: https://github.com/containers/ocicrypt

[8] Open Container Initiative, "Image Encryption Specification (PR #775)," GitHub. Available: https://github.com/opencontainers/image-spec/pull/775

[9] containers/ocicrypt Authors, "blockcipher.go - AES_256_CTR_HMAC_SHA256," GitHub. Available: https://github.com/containers/ocicrypt/blob/main/blockcipher/blockcipher.go

[10] containerd Authors, "imgcrypt - OCI Image Encryption Package," GitHub. Available: https://github.com/containerd/imgcrypt

[11] containers/ocicrypt Authors, "Keyprovider Protocol," GitHub. Available: https://github.com/containers/ocicrypt/blob/main/docs/keyprovider.md

[12] Confidential Containers Project, "Trustee - Key Broker Service," GitHub. Available: https://github.com/confidential-containers/trustee

[13] Kata Containers Project, "How to run Kata Containers with SNP VMs," GitHub. Available: https://github.com/kata-containers/kata-containers/blob/main/docs/how-to/how-to-run-kata-containers-with-SNP-VMs.md

[14] Confidential Containers Project, "image-rs Design Document," GitHub. Available: https://github.com/confidential-containers/guest-components/blob/main/image-rs/docs/design.md

[15] Confidential Containers Project, "Confidential Data Hub," GitHub. Available: https://github.com/confidential-containers/guest-components/tree/main/confidential-data-hub

[16] Confidential Containers Project, "Attestation Agent," GitHub. Available: https://github.com/confidential-containers/guest-components/tree/main/attestation-agent

[17] containerd Authors, "nydus-snapshotter," GitHub. Available: https://github.com/containerd/nydus-snapshotter

[18] Confidential Containers Project, "KBS Attestation Protocol," GitHub. Available: https://github.com/confidential-containers/trustee/blob/main/kbs/docs/kbs_attestation_protocol.md

[19] Confidential Containers Project, "Attestation Agent README," GitHub. Available: https://github.com/confidential-containers/guest-components/tree/main/attestation-agent

[20] containers/ocicrypt Authors, "keyprovider-config/config.go," GitHub. Available: https://github.com/containers/ocicrypt/blob/main/config/keyprovider-config/config.go

[21] containerd Authors, "CRI Decryption," GitHub. Available: https://github.com/containerd/containerd/blob/main/docs/cri/decryption.md
