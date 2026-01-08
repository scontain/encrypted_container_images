# Demo: Pulling Encrypted Container Images in TDX CVMs Without Kata Runtime

This hands-on demo walks through setting up a Kubernetes cluster on Azure Intel TDX-based Confidential VMs, deploying encrypted container images with attestation-gated decryption, and demonstrating both the security properties that work and the isolation limitations compared to full CoCo with Kata runtime.

> **Important: Azure TDX Attestation Model**
>
> On Azure TDX CVMs, attestation works differently than bare-metal TDX:
> - There is **no `/dev/tdx_guest` device** exposed to the guest
> - Instead, attestation flows through a **vTPM** (`/dev/tpm0`, `/dev/tpmrm0`) that is cryptographically backed by Intel TDX
> - The vTPM's attestation key is embedded in the TDX quote, creating a composite trust chain
> - The Attestation Agent must be built with the `az-tdx-vtpm-attester` platform support
>
> This is by design - Azure's architecture ties vTPM evidence to TDX measurements for a unified attestation flow.

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Environment Setup](#2-environment-setup)
3. [Azure Infrastructure](#3-azure-infrastructure)
4. [Kubernetes Cluster Setup](#4-kubernetes-cluster-setup)
5. [Trustee (KBS) Deployment](#5-trustee-kbs-deployment)
6. [Azure Attestation Architecture and Intel Trust Authority](#6-azure-attestation-architecture-and-intel-trust-authority)
7. [Guest Components (AA + CDH) Configuration](#7-guest-components-aa--cdh-configuration)
8. [containerd Configuration for Encrypted Images](#8-containerd-configuration-for-encrypted-images)
9. [Creating and Pushing Encrypted Images](#9-creating-and-pushing-encrypted-images)
10. [Demonstrating Safety Claims (What Works)](#10-demonstrating-safety-claims-what-works)
11. [Demonstrating What We Lose Without Kata](#11-demonstrating-what-we-lose-without-kata)
12. [Cleanup](#12-cleanup)
13. [Troubleshooting](#13-troubleshooting)

---

## 1. Prerequisites

### Required Tools

Install on your local machine:

```bash
# Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# kubectl
curl -LO "https://dl.k8s.io/release/v1.31.0/bin/linux/amd64/kubectl"
chmod +x kubectl && sudo mv kubectl /usr/local/bin/

# Helm
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# skopeo (for image encryption)
sudo apt-get update && sudo apt-get install -y skopeo

# jq (for JSON parsing)
sudo apt-get install -y jq

```

### Azure Requirements

* An Azure subscription with access to Confidential VM sizes
* A **pre-existing resource group** assigned to you
* Sufficient quota for DCedsv5-series VMs in your chosen region
* SSH key pair for VM access

### Docker Hub Account

You'll need a Docker Hub account to push encrypted images:

```bash
docker login

# If using a credential store (common with Docker Desktop), also run:
# This ensures skopeo can authenticate when pushing encrypted images
skopeo login docker.io

```

---

## 2. Environment Setup

Set these environment variables before proceeding. These will be used throughout the demo:

```bash
# REQUIRED: Your pre-assigned resource group
export RESOURCE_GROUP="your-assigned-resource-group"

# REQUIRED: Azure region with TDX support and quota
# Available regions: westeurope, centralus, eastus2, northeurope
export LOCATION="westeurope"

# Network configuration
export VNET_NAME="k8s-vnet"
export CONTROL_PLANE_SUBNET="control-plane-subnet"
export WORKER_SUBNET="worker-subnet"
export NSG_NAME="k8s-nsg"

# VM names
export CONTROL_PLANE_VM="k8s-control-1"
export WORKER_VM="k8s-worker-1"
export KBS_VM="kbs-server"

# Kubernetes configuration
export POD_CIDR="10.244.0.0/16"
export SERVICE_CIDR="10.96.0.0/12"

# Docker Hub configuration
export DOCKER_USERNAME="your-dockerhub-username"
export ENCRYPTED_IMAGE="${DOCKER_USERNAME}/nginx-encrypted:latest"

# SSH user
export VM_USER="azureuser"

```

Verify your Azure login and resource group access:

```bash
az login
az account show

# Verify you have access to the resource group
az group show --name $RESOURCE_GROUP --query "{name:name, location:location}" -o table

```

Check TDX VM availability in your chosen region:

```bash
az vm list-skus \
    --location $LOCATION \
    --size Standard_DC \
    --query "[?family=='standardDCEDSv5Family'].{name:name, vCPUs:capabilities[?name=='vCPUs'].value|[0], memory:capabilities[?name=='MemoryGB'].value|[0]}" \
    -o table

```

---

## 3. Azure Infrastructure

### 3.1 Create Virtual Network

```bash
az network vnet create \
    --resource-group $RESOURCE_GROUP \
    --location $LOCATION \
    --name $VNET_NAME \
    --address-prefix 10.0.0.0/16

az network vnet subnet create \
    --resource-group $RESOURCE_GROUP \
    --vnet-name $VNET_NAME \
    --name $CONTROL_PLANE_SUBNET \
    --address-prefix 10.0.1.0/24

az network vnet subnet create \
    --resource-group $RESOURCE_GROUP \
    --vnet-name $VNET_NAME \
    --name $WORKER_SUBNET \
    --address-prefix 10.0.2.0/24

az network vnet subnet create \
    --resource-group $RESOURCE_GROUP \
    --vnet-name $VNET_NAME \
    --name kbs-subnet \
    --address-prefix 10.0.3.0/24

```

### 3.2 Create Network Security Group

```bash
az network nsg create \
    --resource-group $RESOURCE_GROUP \
    --location $LOCATION \
    --name $NSG_NAME

# SSH access (restrict source IP in production)
az network nsg rule create \
    --resource-group $RESOURCE_GROUP \
    --nsg-name $NSG_NAME \
    --name allow-ssh \
    --priority 1000 \
    --direction Inbound \
    --access Allow \
    --protocol Tcp \
    --destination-port-range 22 \
    --source-address-prefix '*'

# Kubernetes API Server
az network nsg rule create \
    --resource-group $RESOURCE_GROUP \
    --nsg-name $NSG_NAME \
    --name allow-k8s-api \
    --priority 1001 \
    --direction Inbound \
    --access Allow \
    --protocol Tcp \
    --destination-port-range 6443 \
    --source-address-prefix '*'

# Kubelet API (internal)
az network nsg rule create \
    --resource-group $RESOURCE_GROUP \
    --nsg-name $NSG_NAME \
    --name allow-kubelet \
    --priority 1002 \
    --direction Inbound \
    --access Allow \
    --protocol Tcp \
    --destination-port-range 10250 \
    --source-address-prefix 'VirtualNetwork'

# etcd (internal)
az network nsg rule create \
    --resource-group $RESOURCE_GROUP \
    --nsg-name $NSG_NAME \
    --name allow-etcd \
    --priority 1003 \
    --direction Inbound \
    --access Allow \
    --protocol Tcp \
    --destination-port-ranges 2379-2380 \
    --source-address-prefix 'VirtualNetwork'

# KBS service
az network nsg rule create \
    --resource-group $RESOURCE_GROUP \
    --nsg-name $NSG_NAME \
    --name allow-kbs \
    --priority 1004 \
    --direction Inbound \
    --access Allow \
    --protocol Tcp \
    --destination-port-range 8080 \
    --source-address-prefix 'VirtualNetwork'

# NodePort services range
az network nsg rule create \
    --resource-group $RESOURCE_GROUP \
    --nsg-name $NSG_NAME \
    --name allow-nodeports \
    --priority 1005 \
    --direction Inbound \
    --access Allow \
    --protocol Tcp \
    --destination-port-ranges 30000-32767 \
    --source-address-prefix '*'

# Internal VNet traffic
az network nsg rule create \
    --resource-group $RESOURCE_GROUP \
    --nsg-name $NSG_NAME \
    --name allow-vnet-internal \
    --priority 1100 \
    --direction Inbound \
    --access Allow \
    --protocol '*' \
    --destination-port-range '*' \
    --source-address-prefix 'VirtualNetwork'

# Associate NSG with subnets
az network vnet subnet update \
    --resource-group $RESOURCE_GROUP \
    --vnet-name $VNET_NAME \
    --name $CONTROL_PLANE_SUBNET \
    --network-security-group $NSG_NAME

az network vnet subnet update \
    --resource-group $RESOURCE_GROUP \
    --vnet-name $VNET_NAME \
    --name $WORKER_SUBNET \
    --network-security-group $NSG_NAME

az network vnet subnet update \
    --resource-group $RESOURCE_GROUP \
    --vnet-name $VNET_NAME \
    --name kbs-subnet \
    --network-security-group $NSG_NAME

```

### 3.3 Create TDX Confidential VMs

#### Control Plane Node

```bash
az vm create \
    --resource-group $RESOURCE_GROUP \
    --location $LOCATION \
    --name $CONTROL_PLANE_VM \
    --size Standard_DC2eds_v5 \
    --admin-username $VM_USER \
    --generate-ssh-keys \
    --image "Canonical:0001-com-ubuntu-confidential-vm-jammy:22_04-lts-cvm:latest" \
    --security-type ConfidentialVM \
    --os-disk-security-encryption-type VMGuestStateOnly \
    --enable-vtpm true \
    --enable-secure-boot true \
    --vnet-name $VNET_NAME \
    --subnet $CONTROL_PLANE_SUBNET \
    --public-ip-address "${CONTROL_PLANE_VM}-pip" \
    --public-ip-sku Standard

# Get control plane IPs
export CONTROL_PLANE_PUBLIC_IP=$(az vm show -d -g $RESOURCE_GROUP -n $CONTROL_PLANE_VM --query publicIps -o tsv)
export CONTROL_PLANE_PRIVATE_IP=$(az vm show -d -g $RESOURCE_GROUP -n $CONTROL_PLANE_VM --query privateIps -o tsv)

echo "Control Plane Public IP: $CONTROL_PLANE_PUBLIC_IP"
echo "Control Plane Private IP: $CONTROL_PLANE_PRIVATE_IP"

# Open port 6443 for external kubectl access
# This is required in addition to NSG rules for public IP access
az vm open-port \
    --resource-group $RESOURCE_GROUP \
    --name $CONTROL_PLANE_VM \
    --port 6443 \
    --priority 900

```

#### Worker Node

```bash
az vm create \
    --resource-group $RESOURCE_GROUP \
    --location $LOCATION \
    --name $WORKER_VM \
    --size Standard_DC2eds_v5 \
    --admin-username $VM_USER \
    --generate-ssh-keys \
    --image "Canonical:0001-com-ubuntu-confidential-vm-jammy:22_04-lts-cvm:latest" \
    --security-type ConfidentialVM \
    --os-disk-security-encryption-type VMGuestStateOnly \
    --enable-vtpm true \
    --enable-secure-boot true \
    --vnet-name $VNET_NAME \
    --subnet $WORKER_SUBNET \
    --public-ip-address "${WORKER_VM}-pip" \
    --public-ip-sku Standard

# Get worker IP
export WORKER_PUBLIC_IP=$(az vm show -d -g $RESOURCE_GROUP -n $WORKER_VM --query publicIps -o tsv)
export WORKER_PRIVATE_IP=$(az vm show -d -g $RESOURCE_GROUP -n $WORKER_VM --query privateIps -o tsv)

echo "Worker Public IP: $WORKER_PUBLIC_IP (Private: $WORKER_PRIVATE_IP)"

```

#### KBS Server (Non-confidential VM, outside cluster)

```bash
az vm create \
    --resource-group $RESOURCE_GROUP \
    --location $LOCATION \
    --name $KBS_VM \
    --size Standard_D4s_v3 \
    --admin-username $VM_USER \
    --generate-ssh-keys \
    --image "Canonical:0001-com-ubuntu-server-jammy:22_04-lts-gen2:latest" \
    --vnet-name $VNET_NAME \
    --subnet kbs-subnet \
    --public-ip-address "${KBS_VM}-pip" \
    --public-ip-sku Standard

export KBS_PUBLIC_IP=$(az vm show -d -g $RESOURCE_GROUP -n $KBS_VM --query publicIps -o tsv)
export KBS_PRIVATE_IP=$(az vm show -d -g $RESOURCE_GROUP -n $KBS_VM --query privateIps -o tsv)

echo "KBS Server Public IP: $KBS_PUBLIC_IP (Private: $KBS_PRIVATE_IP)"

```

### 3.4 Verify TDX is Enabled

SSH into each Kubernetes node and verify TDX:

```bash
ssh $VM_USER@$CONTROL_PLANE_PUBLIC_IP << 'EOF'
echo "=== Checking TDX Memory Encryption ==="
sudo dmesg | grep -i "Memory Encryption Features active" | head -5

echo -e "\n=== Kernel TDX Messages ==="
sudo dmesg | grep -i tdx | head -10

echo -e "\n=== vTPM Devices (Azure TDX uses vTPM-backed attestation) ==="
ls -la /dev/tpm* 2>/dev/null || echo "TPM devices not found"

echo -e "\n=== TPM Resource Manager ==="
ls -la /dev/tpmrm0 2>/dev/null || echo "TPM resource manager not found"

echo -e "\n=== TSS Group (needed for TPM access) ==="
getent group tss
EOF

```

Expected output should show:

* `Memory Encryption Features active: Intel TDX` in kernel messages
* `/dev/tpm0` and `/dev/tpmrm0` devices exist (vTPM backed by TDX)
* `tss` group exists for TPM access permissions

**Note**: On Azure TDX CVMs, there is no `/dev/tdx_guest` device. Instead, attestation flows through the vTPM (`/dev/tpm0`, `/dev/tpmrm0`) which is cryptographically backed by Intel TDX. The vTPM's attestation key is embedded in the TDX quote, creating a composite trust chain.

---

## 4. Kubernetes Cluster Setup

### 4.1 Install Prerequisites on All Nodes

Create a script and run it on all Kubernetes nodes (control plane and worker):

```bash
# Create the setup script
cat > /tmp/k8s-prereqs.sh << 'SCRIPT'
#!/bin/bash
set -e

echo "=== Disabling Swap ==="
sudo swapoff -a
sudo sed -i '/ swap / s/^/#/' /etc/fstab

echo "=== Loading Kernel Modules ==="
cat <<EOF | sudo tee /etc/modules-load.d/k8s.conf
overlay
br_netfilter
EOF

sudo modprobe overlay
sudo modprobe br_netfilter

echo "=== Configuring Sysctl ==="
cat <<EOF | sudo tee /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward = 1
EOF

sudo sysctl --system

echo "=== Installing containerd ==="
sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates curl gnupg lsb-release

sudo install -m 0755 -d /etc/apt/keyrings
# Added --yes to overwrite existing keys if script is re-run
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install -y containerd.io

echo "=== Configuring containerd ==="
sudo mkdir -p /etc/containerd
containerd config default | sudo tee /etc/containerd/config.toml > /dev/null
sudo sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
sudo systemctl restart containerd
sudo systemctl enable containerd

echo "=== Installing Kubernetes Components ==="
# Added --yes to overwrite existing keys if script is re-run
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.31/deb/Release.key | sudo gpg --dearmor --yes -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.31/deb/ /' | sudo tee /etc/apt/sources.list.d/kubernetes.list

sudo apt-get update
# conntrack is required by kubeadm for kube-proxy/iptables
sudo apt-get install -y kubelet kubeadm kubectl conntrack
sudo apt-mark hold kubelet kubeadm kubectl

echo "=== Installing Build Dependencies ==="
# Remove old golang if present
sudo apt-get remove -y golang-go
sudo apt-get autoremove -y

# Install all build dependencies:
# - git, make: basic build tools
# - libbtrfs-dev, libdevmapper-dev: for imgcrypt
# - clang, libclang-dev, protobuf-compiler: for Attestation Agent (Rust/bindgen)
# - libtss2-dev, pkg-config: for TPM libraries (tss-esapi)
# - musl-tools: for static compilation (musl target)
sudo apt-get install -y git make libbtrfs-dev libdevmapper-dev \
    clang libclang-dev protobuf-compiler \
    libtss2-dev pkg-config musl-tools

echo "=== Installing Latest Go (Required for imgcrypt) ==="
# Fetch the latest stable Go version number
LATEST_GO_VERSION=$(curl -sL 'https://go.dev/VERSION?m=text' | head -n 1)
echo "Detected latest Go version: $LATEST_GO_VERSION"

# Download the latest Go tarball
curl -LO "https://go.dev/dl/${LATEST_GO_VERSION}.linux-amd64.tar.gz"

# Install Go to /usr/local
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf "${LATEST_GO_VERSION}.linux-amd64.tar.gz"
rm "${LATEST_GO_VERSION}.linux-amd64.tar.gz"

# Add Go to PATH for this session
export PATH=$PATH:/usr/local/go/bin

echo "=== Building and Installing imgcrypt (ctd-decoder) ==="
cd /tmp
rm -rf imgcrypt
git clone https://github.com/containerd/imgcrypt.git
cd imgcrypt
make
sudo make install
echo "ctd-decoder installed at: $(which ctd-decoder)"

echo "=== Prerequisites Installation Complete ==="
SCRIPT

chmod +x /tmp/k8s-prereqs.sh

# Run on all nodes
for IP in $CONTROL_PLANE_PUBLIC_IP $WORKER_PUBLIC_IP; do
    echo "=== Installing prerequisites on $IP ==="
    scp /tmp/k8s-prereqs.sh $VM_USER@$IP:/tmp/
    ssh $VM_USER@$IP 'bash /tmp/k8s-prereqs.sh'
done

```

### 4.2 Initialize Control Plane

```bash
ssh $VM_USER@$CONTROL_PLANE_PUBLIC_IP << EOF
sudo kubeadm init \
    --skip-phases=addon/kube-proxy \
    --apiserver-advertise-address=$CONTROL_PLANE_PRIVATE_IP \
    --apiserver-cert-extra-sans=$CONTROL_PLANE_PUBLIC_IP \
    --control-plane-endpoint=$CONTROL_PLANE_PRIVATE_IP:6443 \
    --pod-network-cidr=$POD_CIDR \
    --service-cidr=$SERVICE_CIDR

# Setup kubectl for azureuser
mkdir -p \$HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf \$HOME/.kube/config
sudo chown \$(id -u):\$(id -g) \$HOME/.kube/config

# Display join command
echo ""
echo "=== JOIN COMMAND FOR WORKER ==="
kubeadm token create --print-join-command
EOF

```

Save the join command output for the next step.

### 4.3 Install Cilium CNI

```bash
ssh $VM_USER@$CONTROL_PLANE_PUBLIC_IP << EOF
# Ensure kubectl/helm can find the kubeconfig (new SSH session doesn't have it set)
export KUBECONFIG=\$HOME/.kube/config

# Verify cluster is accessible
kubectl get nodes

# Install Helm
curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# Add Cilium repo
helm repo add cilium https://helm.cilium.io/
helm repo update

# Install Cilium with kube-proxy replacement
helm install cilium cilium/cilium --version 1.16.5 \
    --namespace kube-system \
    --set kubeProxyReplacement=true \
    --set k8sServiceHost=$CONTROL_PLANE_PRIVATE_IP \
    --set k8sServicePort=6443 \
    --set ipam.mode=kubernetes

# Wait for Cilium to be ready
kubectl wait --for=condition=Ready pods -l app.kubernetes.io/name=cilium-agent -n kube-system --timeout=300s
EOF

```

### 4.4 Join Worker Node

Replace `<JOIN_COMMAND>` with the actual join command from step 4.2:

```bash
# Get the join command from control plane
JOIN_CMD=$(ssh $VM_USER@$CONTROL_PLANE_PUBLIC_IP "kubeadm token create --print-join-command")

# Join worker
echo "=== Joining worker at $WORKER_PUBLIC_IP ==="
ssh $VM_USER@$WORKER_PUBLIC_IP "sudo $JOIN_CMD"

```

### 4.5 Verify Cluster Status

```bash
ssh $VM_USER@$CONTROL_PLANE_PUBLIC_IP << 'EOF'
export KUBECONFIG=$HOME/.kube/config

echo "=== Node Status ==="
kubectl get nodes -o wide

echo -e "\n=== System Pods ==="
kubectl get pods -n kube-system

echo -e "\n=== Cilium Status ==="
kubectl -n kube-system exec ds/cilium -- cilium status --brief
EOF

```

### 4.6 Copy kubeconfig Locally

```bash
mkdir -p ~/.kube
scp $VM_USER@$CONTROL_PLANE_PUBLIC_IP:~/.kube/config ~/.kube/config-coco-demo

# Update the server address to use public IP
sed -i "s|server: https://$CONTROL_PLANE_PRIVATE_IP:6443|server: https://$CONTROL_PLANE_PUBLIC_IP:6443|" ~/.kube/config-coco-demo

export KUBECONFIG=~/.kube/config-coco-demo
kubectl get nodes

```

---

## 5. Trustee (KBS) Deployment

Deploy the Key Broker Service on the dedicated KBS VM (outside the Kubernetes cluster).

### 5.1 Install Docker on KBS VM

```bash
ssh $VM_USER@$KBS_PUBLIC_IP << 'EOF'
# Install Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
EOF

# Reconnect to apply group membership
ssh $VM_USER@$KBS_PUBLIC_IP "docker --version"

```

### 5.2 Deploy Trustee with Docker Compose

```bash
ssh $VM_USER@$KBS_PUBLIC_IP << 'OUTER'
# Clone Trustee repository
git clone https://github.com/confidential-containers/trustee.git
cd trustee

# Create directory structure
mkdir -p kbs/config
mkdir -p kbs/repository/default/image_key
mkdir -p attestation-service/policies
mkdir -p rvps/reference-values

# Generate admin keypair
openssl genpkey -algorithm ed25519 -out kbs/config/private.key
openssl pkey -in kbs/config/private.key -pubout -out kbs/config/public.pub

# Create KBS configuration
cat > kbs/config/kbs-config.toml << 'EOF'
[http_server]
sockets = ["0.0.0.0:8080"]
insecure_http = true

[admin]
insecure_api = false
type = "Simple"
auth_public_key = "/opt/confidential-containers/kbs/config/public.pub"

[attestation_token]
insecure_key = true
attestation_token_type = "CoCo"

[attestation_service]
type = "coco_as_builtin"
work_dir = "/opt/confidential-containers/attestation-service"
policy_engine = "opa"

[attestation_service.attestation_token_broker]
type = "Ear"
policy_dir = "/opt/confidential-containers/attestation-service/policies"

[attestation_service.attestation_token_config]
duration_min = 5

[attestation_service.rvps_config]
type = "BuiltIn"

[attestation_service.rvps_config.storage]
type = "LocalJson"
file_path = "/opt/confidential-containers/rvps/reference-values.json"

[[plugins]]
name = "resource"
type = "LocalFs"
dir_path = "/opt/confidential-containers/kbs/repository"

[policy_engine]
policy_path = "/opt/confidential-containers/kbs/policy.rego"
EOF

# Create attestation policy (allow Azure TDX vTPM attestations)
cat > kbs/policy.rego << 'EOF'
package policy

import rego.v1

default allow = false

# Allow Azure TDX vTPM attestations with affirming status
allow if {
    input["submods"]["cpu0"]["ear.status"] == "affirming"
    input["submods"]["cpu0"]["ear.veraison.annotated-evidence"]["az-tdx-vtpm"]
}

# Alternative: Allow based on TDX evidence
allow if {
    input["submods"]["cpu0"]["ear.status"] == "affirming"
    input["submods"]["cpu0"]["ear.veraison.annotated-evidence"]["tdx"]
}

# For demo/testing: also allow sample attester
allow if {
    input["submods"]["cpu0"]["ear.status"] == "affirming"
}
EOF

# Create empty reference values (for demo)
cat > rvps/reference-values.json << 'EOF'
[]
EOF

# Create attestation service policy
mkdir -p attestation-service/policies
cat > attestation-service/policies/default.rego << 'EOF'
package policy

default allow = true
EOF

# Generate encryption key for images (32 bytes)
head -c 32 /dev/urandom > kbs/repository/default/image_key/nginx
echo "Encryption key generated"

# Create Docker Compose file
cat > docker-compose.yml << 'EOF'
services:
  kbs:
    image: ghcr.io/confidential-containers/staged-images/kbs:latest
    ports:
      - "8080:8080"
    volumes:
      - ./kbs/config:/opt/confidential-containers/kbs/config:ro
      - ./kbs/repository:/opt/confidential-containers/kbs/repository:ro
      - ./kbs/policy.rego:/opt/confidential-containers/kbs/policy.rego:ro
      - ./attestation-service:/opt/confidential-containers/attestation-service
      - ./rvps:/opt/confidential-containers/rvps:ro
    command:
      - "/usr/local/bin/kbs"
      - "--config-file"
      - "/opt/confidential-containers/kbs/config/kbs-config.toml"
    restart: unless-stopped
EOF

# Start KBS
docker compose up -d

# Wait for KBS to be ready
sleep 5
docker compose logs

# Test KBS is running
curl -s http://localhost:8080/kbs/v0/resource/default/image_key/nginx > /dev/null && echo "KBS is running (auth required for resources)"

echo ""
echo "=== KBS Deployment Complete ==="
echo "KBS URL: http://$(hostname -I | awk '{print $1}'):8080"
OUTER

```

### 5.3 Copy Encryption Key for Image Creation

```bash
# Copy the encryption key to your local machine
mkdir -p ~/coco-demo
scp $VM_USER@$KBS_PUBLIC_IP:~/trustee/kbs/repository/default/image_key/nginx ~/coco-demo/encryption_key

echo "Encryption key saved to ~/coco-demo/encryption_key"
ls -la ~/coco-demo/encryption_key

```

---

## 6. Azure Attestation Architecture and Intel Trust Authority

### 6.1 Understanding Azure's Attestation Model

**Important Discovery**: Azure TDX attestation uses a different architecture than the upstream Confidential Containers KBS expects.

#### The Architecture Mismatch

| Component | Upstream CoCo (What KBS Expects) | Azure's Approach |
|-----------|----------------------------------|------------------|
| **Attestation Service** | KBS + AS expects standard PCCS | **Microsoft Azure Attestation (MAA)** |
| **Collateral Source** | `https://api.trustedservices.intel.com/` or local PCCS | Azure THIM via `https://global.acccache.azure.net/` |
| **Key Management** | KBS with policy engine | **Azure Key Vault + Secure Key Release (SKR)** |
| **Integration** | Direct DCAP/QPL to PCCS | **Sidecar container + MAA + AKV** |

#### Why This Matters

The upstream KBS and Attestation Service are designed to work with standard Intel PCCS endpoints that provide TCB (Trusted Computing Base) information for TDX platforms. However, Azure's infrastructure uses:

1. **Microsoft Azure Attestation (MAA)** - Azure's proprietary attestation service that supports TDX
2. **Azure THIM (Trusted Hardware Identity Management)** - Serves collateral but uses a different model
3. **Intentional TCB versioning** - Azure THIM provides older TCB info for compatibility, not the latest from Intel

When you try to use the upstream KBS with Azure TDX, the flow breaks:

```
TDX TD → ttrpc-aa → Upstream KBS → attestation-service →
Expects standard PCCS endpoint → ❌ Azure doesn't provide this →
SGX_QL_TCBINFO_NOT_FOUND
```

#### Azure's Designed Attestation Path

Azure provides TDX attestation support through:

- **[Azure Attestation](https://learn.microsoft.com/en-us/azure/attestation/overview)** supports TDX quote verification using PCK Certificates
- **[Azure TDX EAT Profile](https://learn.microsoft.com/en-us/azure/attestation/trust-domain-extensions-eat-profile)** defines TDX-specific claims
- **[Azure Confidential Containers](https://learn.microsoft.com/en-us/azure/container-instances/confidential-containers-attestation-concepts)** use a sidecar approach integrating MAA + Azure Key Vault

### 6.2 Solution Options

#### Option 1: Use Azure's Official Confidential Containers (Recommended for Production)

Deploy using Azure's official confidential containers with MAA integration:
- **[AKS Confidential Containers](https://learn.microsoft.com/en-us/azure/aks/confidential-containers-overview)**
- **[ACI Confidential Containers](https://learn.microsoft.com/en-us/azure/container-instances/container-instances-confidential-overview)**

Benefits:
- Fully supported by Microsoft
- Integrated with Azure Key Vault for Secure Key Release
- Uses MAA for attestation

Limitations:
- Requires adapting to Azure-specific architecture
- May not be compatible with upstream CoCo tooling

#### Option 2: Intel Trust Authority (What We'll Use)

**[Intel Trust Authority](https://docs.trustauthority.intel.com/)** is Intel's attestation service that:
- Offers **FREE subscriptions** for Azure, Google Cloud, and IBM Cloud
- Has native Azure TDX support
- Can integrate with upstream KBS
- Provides **[Azure vTPM attestation support](https://docs.trustauthority.intel.com/main/articles/articles/ita/tutorial-azure-vtpm.html)**

This option allows us to use upstream CoCo components while getting proper TDX attestation on Azure.

#### Option 3: Use offline_fs_kbc (Current Demo Workaround)

For demo purposes, we're using `offline_fs_kbc` which:
- ✅ Works for demonstrating encrypted image pull functionality
- ❌ Provides **no security guarantees** - keys stored in plaintext on disk
- ❌ Not suitable for production
- ✅ Useful for validating the image encryption/decryption workflow

### 6.3 Intel Trust Authority Setup (Recommended Path)

**Comprehensive Setup Guide**: A detailed step-by-step guide for configuring Intel Trust Authority with your Azure TDX CVMs is available at:

**→ [`~/coco-demo/INTEL-TRUST-AUTHORITY-SETUP.md`](/home/laerson/coco-demo/INTEL-TRUST-AUTHORITY-SETUP.md)**

This guide covers:
- Prerequisites and obtaining an Intel Trust Authority API key
- Configuring the CoCo KBS (Trustee) to use Intel Trust Authority as the attestation backend
- Updating attestation-agent from `offline_fs_kbc` to `cc_kbc` mode
- Testing the end-to-end attestation flow
- Troubleshooting common issues

#### Quick Overview

Intel Trust Authority integration involves three main components:

```
┌─────────────────┐      ┌──────────────┐      ┌─────────────────────┐
│ Guest VM (TDX)  │─────>│ CoCo KBS     │─────>│ Intel Trust         │
│                 │      │              │      │ Authority           │
│ - ttrpc-aa      │      │ - Verifies   │      │                     │
│ - CDH           │      │   tokens     │      │ - Verifies TDX      │
│ - cc_kbc        │      │ - Releases   │      │   quote             │
│                 │<─────│   keys       │<─────│ - Issues token      │
└─────────────────┘      └──────────────┘      └─────────────────────┘
```

**Key Steps:**

1. **Register for Intel Trust Authority**
   - Visit [Intel Trust Authority Portal](https://portal.trustauthority.intel.com/)
   - Sign up for a free account
   - Create an Attestation API key

2. **Configure KBS to use Intel Trust Authority**
   ```bash
   cd ~/trustee/kbs/config/kubernetes/
   export DEPLOYMENT_DIR=ita
   export ITA_API_KEY="your-api-key"
   sed -i "s/api_key =.*/api_key = \"${ITA_API_KEY}\"/g" $DEPLOYMENT_DIR/kbs-config.toml
   ./deploy-kbs.sh
   ```

3. **Update Attestation Agent to use cc_kbc**
   ```bash
   # On worker and control plane VMs
   sudo mkdir -p /etc/attestation-agent
   sudo tee /etc/attestation-agent/attestation-agent.conf > /dev/null <<EOF
   [token_configs.coco_as]
   url = "http://${KBS_ADDRESS}:8080"

   [token_configs.kbs]
   url = "http://${KBS_ADDRESS}:8080"
   EOF

   # Update service to use config file
   sudo systemctl restart ttrpc-attestation-agent
   ```

4. **Deploy pods with cc_kbc annotation**
   ```yaml
   apiVersion: v1
   kind: Pod
   metadata:
     name: nginx-encrypted-ita
     annotations:
       io.katacontainers.config.runtime.cc_kbc: "cc_kbc::http://10.0.3.4:8080"
   spec:
     runtimeClassName: kata-cc
     containers:
     - name: nginx
       image: your-username/nginx-encrypted:latest
   ```

**Testing:**
```bash
# Manual attestation test on worker VM
curl -sL https://raw.githubusercontent.com/intel/trustauthority-client-for-go/main/release/install-tdx-cli-azure.sh | sudo bash

cat > /tmp/config.json <<EOF
{
  "trustauthority_api_url": "https://api.trustauthority.intel.com",
  "trustauthority_api_key": "your-api-key",
  "cloud_provider": "azure"
}
EOF

sudo trustauthority-cli token --tdx --tpm -c /tmp/config.json
```

**Important Notes:**
- Azure TDX CVMs require **both** `--tdx` and `--tpm` flags for attestation (vTPM backed by TDX)
- Intel Trust Authority API URLs differ by region (US vs EU)
- The KBS must be reachable from guest VMs (check networking/firewall rules)

**Resources:**
- [Intel Trust Authority Documentation](https://docs.trustauthority.intel.com/)
- [Azure TDX Tutorial](https://docs.trustauthority.intel.com/main/articles/tutorial-tdx.html)
- [Azure vTPM+TDX Tutorial](https://docs.trustauthority.intel.com/main/articles/tutorial-azure-vtpm.html)
- [Intel Confidential Containers Guide](https://cc-enabling.trustedservices.intel.com/intel-confidential-containers-guide/02/infrastructure_setup/)

### 6.4 Current Demo Configuration (offline_fs_kbc)

For this demo, we'll use `offline_fs_kbc` to demonstrate the encrypted image pull workflow without remote attestation. This is acceptable for demo purposes but **should not be used in production**.

**Security Implications**:
- Encryption keys are stored in plaintext in `/etc/aa-offline_fs_kbc-resources.json`
- No attestation verification
- Anyone with root access can read the keys
- This defeats the purpose of confidential computing for production use

**When to use**:
- Validating encrypted image workflows before setting up production attestation
- Testing image encryption/decryption mechanics
- Development and demo environments only

---

## 7. Guest Components (AA + CDH) Configuration

Configure the Attestation Agent (AA) and Confidential Data Hub (CDH) on all Kubernetes nodes.

**Architecture Note:** The modern CoCo guest-components architecture uses two services working together:
- **Confidential Data Hub (CDH)** - Implements the keyprovider gRPC protocol (port 50000) that containerd/ocicrypt uses for image decryption. CDH coordinates secret retrieval and calls AA for attestation.
- **Attestation Agent (AA)** - Handles TEE attestation via ttrpc protocol (unix socket), called by CDH when attestation is needed to retrieve keys from KBS.

The flow is: `ctd-decoder` (containerd's stream processor) → `grpc-cdh` (port 50000) → `ttrpc-aa` (unix socket) → `KBS` (remote attestation + key retrieval).

**Important:**
- CDH must be built with `grpc` feature to listen on TCP port 50000 for the keyprovider protocol
- AA must be built with `ttrpc` feature to communicate with CDH via unix socket (CDH's cc_kbc expects ttrpc)
- For Azure TDX, both must be built with `az-tdx-vtpm-attester` feature

### 7.1 Build and Install Guest Components

```bash
cat > /tmp/install-guest-components.sh << 'SCRIPT'
#!/bin/bash
set -e

echo "=== Installing Rust ==="
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source $HOME/.cargo/env

echo "=== Installing Build Dependencies ==="
sudo apt-get update
# Note: Full dependencies were installed in Step 4.1, but we ensure they are present here
sudo apt-get install -y protobuf-compiler libprotobuf-dev pkg-config libssl-dev \
    libtss2-dev tpm2-tools clang libclang-dev

echo "=== Adding user to tss group for TPM access ==="
sudo usermod -aG tss $USER

echo "=== Cloning Guest Components ==="
cd /tmp
rm -rf guest-components
git clone https://github.com/confidential-containers/guest-components.git
cd guest-components

echo "=== Building Guest Components for Azure TDX vTPM ==="
# Build ttrpc-aa and grpc-cdh for native target (glibc, not musl)
# Note: The Makefile defaults to musl static builds which require cross-compilation
# setup. For Ubuntu VMs, native glibc builds work fine and are simpler.
#
# Why these specific binaries?
# - ttrpc-aa: AA in ttrpc mode (unix socket) - required by CDH's cc_kbc
# - grpc-cdh: CDH in gRPC mode (TCP port 50000) - implements keyprovider protocol
#
# Features enabled:
# - attestation-agent: bin, ttrpc, az-tdx-vtpm-attester
# - confidential-data-hub: bin, grpc, kbs
cargo build --release \
    -p attestation-agent --bin ttrpc-aa \
    -p confidential-data-hub --bin grpc-cdh \
    --features "attestation-agent/bin,attestation-agent/ttrpc,attestation-agent/az-tdx-vtpm-attester,confidential-data-hub/bin,confidential-data-hub/grpc,confidential-data-hub/kbs"

echo "=== Installing Guest Components ==="
sudo install -m 0755 target/release/ttrpc-aa /usr/local/bin/attestation-agent
sudo install -m 0755 target/release/grpc-cdh /usr/local/bin/confidential-data-hub

echo "=== Verifying Installation ==="
echo "Installed binaries:"
ls -la /usr/local/bin/attestation-agent /usr/local/bin/confidential-data-hub

echo "=== Guest Components Installation Complete ==="
echo "NOTE: You may need to log out and back in for tss group membership to take effect"
SCRIPT

chmod +x /tmp/install-guest-components.sh

# Run on all Kubernetes nodes
for IP in $CONTROL_PLANE_PUBLIC_IP $WORKER_PUBLIC_IP; do
    echo "=== Installing Guest Components on $IP ==="
    scp /tmp/install-guest-components.sh $VM_USER@$IP:/tmp/
    ssh $VM_USER@$IP 'bash /tmp/install-guest-components.sh'
done
```

### 7.2 Configure and Start Attestation Agent

The Attestation Agent handles TEE attestation requests from CDH via ttrpc protocol (unix socket).

```bash
cat > /tmp/configure-aa.sh << 'SCRIPT'
#!/bin/bash
set -e

echo "=== Creating Attestation Agent Configuration ==="
sudo mkdir -p /etc/attestation-agent

# AA configuration - ttrpc mode
# CDH's cc_kbc expects AA on unix socket at /run/confidential-containers/attestation-agent/attestation-agent.sock
sudo tee /etc/attestation-agent/config.toml > /dev/null << 'EOF'
# Attestation Agent Configuration for Azure TDX vTPM (ttrpc mode)
# AA handles attestation requests from CDH via unix socket

# No additional config needed - ttrpc-aa uses default unix socket path
EOF

echo "=== Creating AA Systemd Service ==="
sudo tee /etc/systemd/system/attestation-agent.service > /dev/null << 'EOF'
[Unit]
Description=Confidential Containers Attestation Agent (ttrpc)
After=network.target

[Service]
Type=simple
Environment="RUST_LOG=attestation_agent=info,kbs_protocol=debug"
ExecStart=/usr/local/bin/attestation-agent -c /etc/attestation-agent/config.toml
Restart=always
RestartSec=5
SupplementaryGroups=tss

[Install]
WantedBy=multi-user.target
EOF

echo "=== Starting Attestation Agent ==="
sudo systemctl daemon-reload
sudo systemctl enable attestation-agent
sudo systemctl restart attestation-agent

sleep 3
sudo systemctl status attestation-agent --no-pager

echo "=== Verifying AA unix socket exists ==="
sudo ls -la /run/confidential-containers/attestation-agent/attestation-agent.sock && echo "AA unix socket created" || echo "WARNING: AA socket not found"

echo "=== Attestation Agent Configuration Complete ==="
SCRIPT

chmod +x /tmp/configure-aa.sh

# Run on all Kubernetes nodes
for IP in $CONTROL_PLANE_PUBLIC_IP $WORKER_PUBLIC_IP; do
    echo "=== Configuring Attestation Agent on $IP ==="
    scp /tmp/configure-aa.sh $VM_USER@$IP:/tmp/
    ssh $VM_USER@$IP 'bash /tmp/configure-aa.sh'
done
```

### 7.3 Configure and Start Confidential Data Hub (CDH)

CDH implements the keyprovider gRPC protocol that containerd uses for image decryption.

```bash
cat > /tmp/configure-cdh.sh << SCRIPT
#!/bin/bash
set -e

KBS_URL="http://$KBS_PRIVATE_IP:8080"

echo "=== Creating CDH Configuration ==="
# IMPORTANT: CDH requires .json extension for config file
sudo tee /etc/confidential-data-hub.json > /dev/null << EOF
{
    "socket": "127.0.0.1:50000",
    "kbc": {
        "name": "cc_kbc",
        "url": "\$KBS_URL"
    },
    "image": {
        "max_concurrent_layer_downloads_per_image": 3,
        "work_dir": "/run/image-rs"
    }
}
EOF

echo "=== Creating CDH Systemd Service ==="
sudo tee /etc/systemd/system/confidential-data-hub.service > /dev/null << 'EOF'
[Unit]
Description=Confidential Data Hub (CDH) gRPC Service
After=network.target attestation-agent.service
Requires=attestation-agent.service

[Service]
Type=simple
Environment="RUST_LOG=debug"
ExecStart=/usr/local/bin/confidential-data-hub -c /etc/confidential-data-hub.json
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

echo "=== Starting Confidential Data Hub ==="
sudo systemctl daemon-reload
sudo systemctl enable confidential-data-hub
sudo systemctl restart confidential-data-hub

sleep 3
sudo systemctl status confidential-data-hub --no-pager

echo "=== Verifying CDH is listening on keyprovider port ==="
nc -zv 127.0.0.1 50000 && echo "CDH listening on port 50000 (keyprovider)" || echo "WARNING: CDH not listening"

echo "=== Confidential Data Hub Configuration Complete ==="
SCRIPT

chmod +x /tmp/configure-cdh.sh

# Run on all Kubernetes nodes
for IP in $CONTROL_PLANE_PUBLIC_IP $WORKER_PUBLIC_IP; do
    echo "=== Configuring CDH on $IP ==="
    scp /tmp/configure-cdh.sh $VM_USER@$IP:/tmp/
    ssh $VM_USER@$IP 'bash /tmp/configure-cdh.sh'
done
```

### 7.4 Create OCIcrypt Keyprovider Configuration

```bash
cat > /tmp/configure-ocicrypt.sh << 'SCRIPT'
#!/bin/bash
set -e

echo "=== Creating OCIcrypt Keyprovider Configuration ==="
sudo mkdir -p /etc/containerd/ocicrypt/keys

sudo tee /etc/containerd/ocicrypt/ocicrypt_keyprovider.conf > /dev/null << 'EOF'
{
  "key-providers": {
    "attestation-agent": {
      "grpc": "127.0.0.1:50000"
    }
  }
}
EOF

echo "=== OCIcrypt Configuration Complete ==="
cat /etc/containerd/ocicrypt/ocicrypt_keyprovider.conf
SCRIPT

chmod +x /tmp/configure-ocicrypt.sh

# Run on all Kubernetes nodes
for IP in $CONTROL_PLANE_PUBLIC_IP $WORKER_PUBLIC_IP; do
    echo "=== Configuring OCIcrypt on $IP ==="
    scp /tmp/configure-ocicrypt.sh $VM_USER@$IP:/tmp/
    ssh $VM_USER@$IP 'bash /tmp/configure-ocicrypt.sh'
done

```

---

## 8. containerd Configuration for Encrypted Images

### 8.1 Update containerd Configuration

```bash
cat > /tmp/configure-containerd.sh << 'SCRIPT'
#!/bin/bash
set -e

echo "=== Backing Up Current containerd Config ==="
sudo cp /etc/containerd/config.toml /etc/containerd/config.toml.backup

echo "=== Creating New containerd Configuration ==="
sudo tee /etc/containerd/config.toml > /dev/null << 'EOF'
version = 2

root = "/var/lib/containerd"
state = "/run/containerd"

[grpc]
  address = "/run/containerd/containerd.sock"

[plugins]
  [plugins."io.containerd.grpc.v1.cri"]
    sandbox_image = "registry.k8s.io/pause:3.9"
    
    [plugins."io.containerd.grpc.v1.cri".containerd]
      snapshotter = "overlayfs"
      default_runtime_name = "runc"
      
      [plugins."io.containerd.grpc.v1.cri".containerd.runtimes]
        [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc]
          runtime_type = "io.containerd.runc.v2"
          [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options]
            SystemdCgroup = true

    [plugins."io.containerd.grpc.v1.cri".image_decryption]
      key_model = "node"

[stream_processors]
  [stream_processors."io.containerd.ocicrypt.decoder.v1.tar.gzip"]
    accepts = ["application/vnd.oci.image.layer.v1.tar+gzip+encrypted"]
    returns = "application/vnd.oci.image.layer.v1.tar+gzip"
    path = "/usr/local/bin/ctd-decoder"
    args = ["--decryption-keys-path", "/etc/containerd/ocicrypt/keys"]
    env = ["OCICRYPT_KEYPROVIDER_CONFIG=/etc/containerd/ocicrypt/ocicrypt_keyprovider.conf"]

  [stream_processors."io.containerd.ocicrypt.decoder.v1.tar.zstd"]
    accepts = ["application/vnd.oci.image.layer.v1.tar+zstd+encrypted"]
    returns = "application/vnd.oci.image.layer.v1.tar+zstd"
    path = "/usr/local/bin/ctd-decoder"
    args = ["--decryption-keys-path", "/etc/containerd/ocicrypt/keys"]
    env = ["OCICRYPT_KEYPROVIDER_CONFIG=/etc/containerd/ocicrypt/ocicrypt_keyprovider.conf"]

  [stream_processors."io.containerd.ocicrypt.decoder.v1.tar"]
    accepts = ["application/vnd.oci.image.layer.v1.tar+encrypted"]
    returns = "application/vnd.oci.image.layer.v1.tar"
    path = "/usr/local/bin/ctd-decoder"
    args = ["--decryption-keys-path", "/etc/containerd/ocicrypt/keys"]
    env = ["OCICRYPT_KEYPROVIDER_CONFIG=/etc/containerd/ocicrypt/ocicrypt_keyprovider.conf"]
EOF

echo "=== Restarting containerd ==="
sudo systemctl restart containerd
sleep 3
sudo systemctl status containerd --no-pager

echo "=== containerd Configuration Complete ==="
SCRIPT

chmod +x /tmp/configure-containerd.sh

# Run on all Kubernetes nodes
for IP in $CONTROL_PLANE_PUBLIC_IP $WORKER_PUBLIC_IP; do
    echo "=== Configuring containerd on $IP ==="
    scp /tmp/configure-containerd.sh $VM_USER@$IP:/tmp/
    ssh $VM_USER@$IP 'bash /tmp/configure-containerd.sh'
done

```

### 8.2 Verify Configuration

```bash
for IP in $CONTROL_PLANE_PUBLIC_IP $WORKER_PUBLIC_IP; do
    echo "=== Verifying $IP ==="
    ssh $VM_USER@$IP << 'EOF'
echo "containerd status:"
sudo systemctl is-active containerd

echo -e "\nAttestation Agent status:"
sudo systemctl is-active attestation-agent

echo -e "\nStream processors configured:"
grep -A 3 'stream_processors' /etc/containerd/config.toml | head -10

echo -e "\nOCIcrypt config:"
cat /etc/containerd/ocicrypt/ocicrypt_keyprovider.conf
EOF
    echo ""
done

```

---

## 9. Creating and Pushing Encrypted Images

### 9.1 Set Up Local Encryption Environment

On your local machine:

```bash
cd ~/coco-demo

# Install CoCo keyprovider for encryption
git clone https://github.com/confidential-containers/guest-components.git
cd guest-components

# Build keyprovider from workspace root
# Note: In a Cargo workspace, binaries are built in the root target/ directory
cargo build --release -p coco_keyprovider

# Verify the binary exists
ls -la target/release/coco_keyprovider

# Start keyprovider for encryption (background)
RUST_LOG=coco_keyprovider ./target/release/coco_keyprovider --socket 127.0.0.1:50000 &
KEYPROVIDER_PID=$!

# Wait for it to start
sleep 2

# Verify it's running
if nc -z 127.0.0.1 50000; then
    echo "Keyprovider started successfully on port 50000"
else
    echo "ERROR: Keyprovider failed to start"
    exit 1
fi

cd ~/coco-demo

# Create ocicrypt configuration
cat > ocicrypt.conf << 'EOF'
{
  "key-providers": {
    "attestation-agent": {
      "grpc": "127.0.0.1:50000"
    }
  }
}
EOF

export OCICRYPT_KEYPROVIDER_CONFIG="$(pwd)/ocicrypt.conf"

```

### 9.2 Encrypt and Push Image

```bash
# Define key ID (matches KBS repository path)
KEY_ID="kbs:///default/image_key/nginx"

# Encrypt the nginx image
skopeo copy --insecure-policy \
    --encryption-key provider:attestation-agent:keypath=$(pwd)/encryption_key::keyid=${KEY_ID} \
    docker://docker.io/library/nginx:stable \
    oci:nginx_encrypted:latest

# Verify encryption
echo "=== Verifying Encryption ==="
skopeo inspect oci:nginx_encrypted:latest | jq '.LayersData[0].Annotations'

# Check for encryption annotation
skopeo inspect oci:nginx_encrypted:latest | jq -r \
    '.LayersData[0].Annotations["org.opencontainers.image.enc.keys.provider.attestation-agent"]' \
    | base64 -d | jq .

# Push to Docker Hub
# Option 1: If you've already run 'docker login', skopeo can use Docker's auth file
skopeo copy --dest-authfile ~/.docker/config.json \
    oci:nginx_encrypted:latest \
    docker://docker.io/${ENCRYPTED_IMAGE}

# Option 2: If Option 1 fails (credential store), login with skopeo directly:
# skopeo login docker.io -u ${DOCKER_USERNAME}
# skopeo copy oci:nginx_encrypted:latest docker://docker.io/${ENCRYPTED_IMAGE}

# Option 3: Provide credentials directly (will prompt for password):
# skopeo copy --dest-creds ${DOCKER_USERNAME} \
#     oci:nginx_encrypted:latest \
#     docker://docker.io/${ENCRYPTED_IMAGE}

echo "=== Encrypted image pushed to: docker.io/${ENCRYPTED_IMAGE} ==="

# Stop local keyprovider
kill $KEYPROVIDER_PID 2>/dev/null

```

### 9.3 Create a Secret Application Image

Let's also create an encrypted image with a secret file inside:

```bash
# Create a simple app with secrets
mkdir -p secret-app
cat > secret-app/Dockerfile << 'EOF'
FROM alpine:latest
RUN mkdir -p /app/secrets
RUN echo "API_KEY=super-secret-key-12345" > /app/secrets/api_key
RUN echo "DB_PASSWORD=database-password-xyz" > /app/secrets/db_creds
COPY entrypoint.sh /app/
RUN chmod +x /app/entrypoint.sh
CMD ["/app/entrypoint.sh"]
EOF

cat > secret-app/entrypoint.sh << 'EOF'
#!/bin/sh
echo "Secret App Running"
echo "Secrets are stored in /app/secrets/"
while true; do sleep 3600; done
EOF

# Build the image
cd secret-app
docker build -t secret-app:latest .

# Save to OCI format
docker save secret-app:latest -o secret-app.tar
skopeo copy docker-archive:secret-app.tar oci:secret-app-oci:latest

cd ~/coco-demo

# Start keyprovider again (binary is in workspace root target directory)
cd guest-components
RUST_LOG=coco_keyprovider ./target/release/coco_keyprovider --socket 127.0.0.1:50000 &
KEYPROVIDER_PID=$!
cd ~/coco-demo

# Encrypt the secret app
skopeo copy --insecure-policy \
    --encryption-key provider:attestation-agent:keypath=$(pwd)/encryption_key::keyid=${KEY_ID} \
    oci:secret-app/secret-app-oci:latest \
    oci:secret-app-encrypted:latest

# Push to Docker Hub
export SECRET_APP_IMAGE="${DOCKER_USERNAME}/secret-app-encrypted:latest"
skopeo copy --dest-authfile ~/.docker/config.json \
    oci:secret-app-encrypted:latest \
    docker://docker.io/${SECRET_APP_IMAGE}

kill $KEYPROVIDER_PID 2>/dev/null

echo "=== Secret app encrypted image pushed to: docker.io/${SECRET_APP_IMAGE} ==="

```

---

## 10. Demonstrating Safety Claims (What Works)

### 10.1 Deploy Encrypted Workload

```bash
cat << EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: encrypted-nginx
  labels:
    app: encrypted-nginx
spec:
  containers:
  - name: nginx
    image: docker.io/${ENCRYPTED_IMAGE}
    imagePullPolicy: Always
    ports:
    - containerPort: 80
EOF

# Watch the pod come up
kubectl get pods -w

```

### 10.2 Observe Attestation Flow

```bash
# Check Attestation Agent logs on the node where pod is running
NODE=$(kubectl get pod encrypted-nginx -o jsonpath='{.spec.nodeName}')
NODE_IP=$(kubectl get node $NODE -o jsonpath='{.status.addresses[?(@.type=="ExternalIP")].address}')

echo "Pod running on node: $NODE ($NODE_IP)"

ssh $VM_USER@$NODE_IP << 'EOF'
echo "=== Recent Attestation Agent Logs ==="
sudo journalctl -u attestation-agent --since "5 minutes ago" | grep -E "(auth|attest|key|resource)" | tail -30
EOF

```

### 10.3 Check KBS Logs for Key Release

```bash
ssh $VM_USER@$KBS_PUBLIC_IP << 'EOF'
echo "=== KBS Logs (Key Requests) ==="
cd ~/trustee
docker compose logs --tail 50 | grep -E "(POST|GET|auth|attest|resource)"
EOF

```

### 10.4 Verify Decryption Worked

```bash
# Verify the container is running
kubectl exec encrypted-nginx -- nginx -v

# Access the nginx welcome page
kubectl port-forward pod/encrypted-nginx 8080:80 &
sleep 2
curl http://localhost:8080 | head -20
kill %1

echo "=== SUCCESS: Encrypted image was decrypted and is running ==="

```

### 10.5 Deploy Secret Application

```bash
cat << EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: secret-app
  labels:
    app: secret-app
spec:
  containers:
  - name: app
    image: docker.io/${SECRET_APP_IMAGE}
    imagePullPolicy: Always
EOF

kubectl wait --for=condition=Ready pod/secret-app --timeout=120s

# Verify secrets are accessible inside the container
kubectl exec secret-app -- cat /app/secrets/api_key
kubectl exec secret-app -- cat /app/secrets/db_creds

echo "=== SUCCESS: Secret application with encrypted image is running ==="

```

### 10.6 Demonstrate Attestation Blocking (Failed Attestation)

**Note:** This demonstration requires production attestation mode with a Key Broker Service (KBS). Since this demo uses `offline_fs_kbc` for development, attestation blocking cannot be demonstrated.

```bash
echo "=== Section 10.6: Attestation Blocking Demonstration ==="
echo ""
echo "⚠️  SKIPPED: This section requires production attestation setup."
echo ""
echo "Current configuration:"
echo "  - Mode: offline_fs_kbc (development mode)"
echo "  - Keys: Stored locally in /etc/aa-offline_fs_kbc-resources.json"
echo "  - KBS: Not contacted for key release"
echo "  - Attestation: No remote attestation performed"
echo ""
echo "Why attestation blocking cannot be demonstrated:"
echo "  1. offline_fs_kbc reads keys from local file"
echo "  2. No connection to remote KBS"
echo "  3. Policy changes would have no effect"
echo "  4. Pods will succeed as long as local keys exist"
echo ""
echo "To demonstrate attestation-gated key release, you need:"
echo "  ✓ Production attestation service (Intel Trust Authority or Azure MAA)"
echo "  ✓ Key Broker Service (KBS) with policy engine"
echo "  ✓ Attestation Agent configured with cc_kbc mode"
echo "  ✓ Network connectivity between guest VMs and KBS"
echo ""
echo "Setup guides:"
echo "  - Intel Trust Authority: ~/coco-demo/INTEL-TRUST-AUTHORITY-SETUP.md"
echo "  - Azure MAA: ~/coco-demo/AZURE-MAA-SETUP.md"
echo "  - Decision guide: ~/coco-demo/ATTESTATION-OPTIONS-SUMMARY.md"
echo ""
echo "With production attestation, this demo would show:"
echo "  1. Change KBS policy to deny all requests"
echo "  2. Deploy encrypted pod"
echo "  3. Pod fails to start (attestation denied)"
echo "  4. Events show 'Failed to pull image' or 'attestation failed'"
echo "  5. Restore policy"
echo "  6. Pod starts successfully"
echo ""
echo "=== Continuing to Section 11: Security Demonstrations ==="
echo ""

```

---

## 11. Demonstrating What We Lose Without Kata

This section demonstrates the security properties that are **LOST** when not using Kata runtime with per-pod TEE isolation.

### 11.1 Shared TEE Boundary - Container Escape Demo

**Risk**: All containers share the same CVM. A privileged container can escape and access all other containers.

```bash
# Deploy a "high security" workload
cat << EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: high-security-app
  labels:
    security: high
spec:
  containers:
  - name: app
    image: docker.io/${SECRET_APP_IMAGE}
    imagePullPolicy: Always
EOF

# Deploy an "attacker" pod with elevated privileges
cat << EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: attacker-pod
  labels:
    security: low
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - name: attacker
    image: ubuntu:latest
    command: ["sleep", "infinity"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: host-root
      mountPath: /host
  volumes:
  - name: host-root
    hostPath:
      path: /
EOF

kubectl wait --for=condition=Ready pod/high-security-app --timeout=120s
kubectl wait --for=condition=Ready pod/attacker-pod --timeout=120s

echo "=== DEMONSTRATING CONTAINER ESCAPE ==="

# From attacker pod, access the host
kubectl exec -it attacker-pod -- bash << 'INNER'
echo "=== Attacker has escaped to host namespace ==="
echo "Hostname: $(hostname)"
echo ""

echo "=== Finding all container processes ==="
ps aux | grep -E "(nginx|secret|entrypoint)" | head -10
echo ""

echo "=== Accessing other container filesystems via /proc ==="
# Find the secret-app process
SECRET_PID=$(pgrep -f "entrypoint" | head -1)
if [ -n "$SECRET_PID" ]; then
    echo "Found secret-app process: $SECRET_PID"
    echo ""
    echo "=== READING SECRETS FROM ANOTHER CONTAINER ==="
    cat /proc/$SECRET_PID/root/app/secrets/api_key
    cat /proc/$SECRET_PID/root/app/secrets/db_creds
    echo ""
    echo "=== Environment variables of secret-app ==="
    cat /proc/$SECRET_PID/environ | tr '\0' '\n' | head -20
fi
INNER

echo ""
echo "=== IMPACT: With Kata, each pod runs in separate VM - this escape is IMPOSSIBLE ==="

```

### 11.2 No Per-Pod Attestation Identity

**Risk**: All pods share the same CVM's attestation identity. KBS cannot distinguish between pods.

```bash
echo "=== DEMONSTRATING SHARED ATTESTATION IDENTITY ==="

# On Azure TDX, attestation uses vTPM - all pods share the same vTPM identity
# Get TPM PCR values from two different pods (via host access)
kubectl exec attacker-pod -- bash -c '
echo "Reading TPM PCR values from host..."
if [ -e /host/dev/tpmrm0 ]; then
    # All pods on this CVM share the same TPM identity
    tpm2_pcrread sha256:0,1,2,3 2>/dev/null || echo "TPM PCR read requires tpm2-tools"
else
    echo "TPM device not accessible from this container"
fi
'

echo ""
echo "=== KEY INSIGHT ==="
echo "Both high-security-app and attacker-pod share the SAME:"
echo "  - vTPM device (/dev/tpm0, /dev/tpmrm0)"
echo "  - TPM attestation key (AK)"
echo "  - TDX measurements backing the vTPM"
echo ""
echo "=== RESULT: Both pods have IDENTICAL attestation identity ==="
echo "=== KBS cannot apply different policies to different pods ==="
echo "=== With Kata: Each pod has UNIQUE attestation identity ==="

```

### 11.3 No Per-Pod Key Policies

**Risk**: Any pod can request any key from KBS since they all have the same identity.

```bash
echo "=== DEMONSTRATING SHARED KEY ACCESS ==="

# Deploy two pods that "should" have different key access
cat << EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: tenant-a-app
  labels:
    tenant: a
spec:
  containers:
  - name: app
    image: docker.io/${SECRET_APP_IMAGE}
    imagePullPolicy: Always
---
apiVersion: v1
kind: Pod
metadata:
  name: tenant-b-app
  labels:
    tenant: b
spec:
  containers:
  - name: app
    image: alpine:latest
    command: ["sleep", "infinity"]
EOF

kubectl wait --for=condition=Ready pod/tenant-a-app --timeout=120s
kubectl wait --for=condition=Ready pod/tenant-b-app --timeout=120s

echo ""
echo "Tenant A's encrypted image was decrypted successfully."
echo "In a proper multi-tenant setup, Tenant B should NOT be able to access Tenant A's keys."
echo ""
echo "However, since both pods share the same CVM attestation identity,"
echo "if Tenant B could make requests to KBS, they would get the SAME keys as Tenant A."
echo ""
echo "=== With Kata: Each tenant's pod has unique attestation, KBS can enforce per-tenant policies ==="

```

### 11.4 No Agent Policy Enforcement (kubectl exec unrestricted)

**Risk**: Unlike Kata's agent policy, there's no restriction on kubectl exec.

```bash
echo "=== DEMONSTRATING UNRESTRICTED EXEC ACCESS ==="

# In Kata CoCo, ExecProcessRequest is blocked by default
# Without Kata, exec works unrestricted

echo "Executing commands in secret-app pod (would be blocked in Kata CoCo):"
echo ""

echo "1. Reading secrets:"
kubectl exec secret-app -- cat /app/secrets/api_key

echo ""
echo "2. Reading environment variables:"
kubectl exec secret-app -- env | head -10

echo ""
echo "3. Reading process command line (exposes arguments):"
kubectl exec secret-app -- cat /proc/1/cmdline | tr '\0' ' '

echo ""
echo "4. Installing tools and exfiltrating data:"
kubectl exec secret-app -- sh -c 'apk add --no-cache curl 2>/dev/null; echo "Could install tools to exfiltrate secrets"'

echo ""
echo "=== With Kata CoCo: Agent policy would BLOCK ExecProcessRequest by default ==="
echo "=== Policy example: default ExecProcessRequest := false ==="

```

### 11.5 Shared Namespace Risks

**Risk**: Pods can be configured to share namespaces, exposing secrets.

```bash
echo "=== DEMONSTRATING SHARED NAMESPACE RISKS ==="

# Deploy pods with shared process namespace
cat << EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: shared-ns-demo
spec:
  shareProcessNamespace: true
  containers:
  - name: secret-holder
    image: alpine:latest
    command: ["/bin/sh", "-c"]
    args: ["export SECRET_TOKEN=super-secret-token-xyz; while true; do sleep 3600; done"]
  - name: observer
    image: alpine:latest
    command: ["sleep", "infinity"]
EOF

kubectl wait --for=condition=Ready pod/shared-ns-demo --timeout=60s

echo ""
echo "From the observer container, accessing secret-holder's environment:"
kubectl exec shared-ns-demo -c observer -- sh -c '
    echo "=== Processes visible (shared PID namespace) ==="
    ps aux
    echo ""
    echo "=== Reading environment of other container ==="
    # Find the sleep process from secret-holder
    for pid in $(ls /proc | grep -E "^[0-9]+$"); do
        if [ -f /proc/$pid/environ ]; then
            env_content=$(cat /proc/$pid/environ 2>/dev/null | tr "\0" "\n")
            if echo "$env_content" | grep -q "SECRET_TOKEN"; then
                echo "Found secret in PID $pid:"
                echo "$env_content" | grep SECRET_TOKEN
            fi
        fi
    done
'

echo ""
echo "=== IMPACT: In shared namespace, secrets from one container are visible to another ==="
echo "=== With Kata: Each container runs in isolated environment within the pod VM ==="

```

### 11.6 Memory Access Across Containers

**Risk**: All containers share the same memory space within the CVM.

```bash
echo "=== DEMONSTRATING SHARED MEMORY SPACE ==="

# This demonstrates that a privileged container can dump memory of other containers
kubectl exec attacker-pod -- bash << 'INNER'
echo "=== Attacker can access memory of all processes on the CVM ==="

# Find a target process
TARGET_PID=$(pgrep -f "nginx" | head -1)
if [ -n "$TARGET_PID" ]; then
    echo "Target nginx process: $TARGET_PID"
    echo ""
    echo "=== Memory maps of nginx process ==="
    cat /proc/$TARGET_PID/maps | head -20
    echo ""
    echo "In a real attack, the attacker could:"
    echo "  1. Dump process memory with gcore"
    echo "  2. Search for secrets, keys, tokens"
    echo "  3. Access decrypted image data in memory"
fi

echo ""
echo "=== With Kata: Each pod's memory is in a SEPARATE encrypted VM ==="
echo "=== Hardware memory encryption (TDX/SEV) isolates pod memory ==="
INNER

```

### 11.7 Summary Comparison

```bash
echo ""
echo "============================================================"
echo "         SECURITY COMPARISON: CVM-only vs Kata CoCo         "
echo "============================================================"
echo ""
echo "| Security Property              | CVM-only | Kata CoCo |"
echo "|--------------------------------|----------|-----------|"
echo "| TEE boundary                   | Shared   | Per-pod   |"
echo "| Container escape protection    | ❌ NONE   | ✅ VM isolated |"
echo "| Attestation identity           | Shared   | Per-pod   |"
echo "| Per-pod key policies in KBS    | ❌ NO     | ✅ YES    |"
echo "| ExecProcessRequest blocking    | ❌ NO     | ✅ YES    |"
echo "| Memory isolation between pods  | ❌ NO     | ✅ YES    |"
echo "| Process namespace isolation    | ❌ Weak   | ✅ Strong |"
echo "| Multi-tenant safe              | ❌ NO     | ✅ YES    |"
echo ""
echo "CONCLUSION:"
echo "  - CVM-only approach is suitable for SINGLE-TENANT deployments"
echo "  - All workloads must trust each other"
echo "  - For multi-tenant or zero-trust: USE KATA CoCo"
echo ""

```

---

## 12. Cleanup

### 12.1 Delete Kubernetes Resources

```bash
kubectl delete pod --all --force --grace-period=0

```

### 12.2 Delete Azure Resources

```bash
# Delete VMs
for VM in $CONTROL_PLANE_VM $WORKER_VM $KBS_VM; do
    az vm delete --resource-group $RESOURCE_GROUP --name $VM --yes --no-wait
done

# Wait for VM deletion
sleep 60

# Delete NICs
for VM in $CONTROL_PLANE_VM $WORKER_VM $KBS_VM; do
    az network nic delete --resource-group $RESOURCE_GROUP --name "${VM}VMNic" --no-wait 2>/dev/null
done

# Delete public IPs
for VM in $CONTROL_PLANE_VM $WORKER_VM $KBS_VM; do
    az network public-ip delete --resource-group $RESOURCE_GROUP --name "${VM}-pip" --no-wait 2>/dev/null
done

# Delete NSG
az network nsg delete --resource-group $RESOURCE_GROUP --name $NSG_NAME --no-wait

# Delete VNet
az network vnet delete --resource-group $RESOURCE_GROUP --name $VNET_NAME --no-wait

echo "=== Cleanup initiated. Resources will be deleted in background. ==="

```

### 12.3 Local Cleanup

```bash
rm -rf ~/coco-demo
rm -f ~/.kube/config-coco-demo

```

---

## 13. Troubleshooting

### 13.1 TDX Not Enabled or vTPM Not Found

```bash
# Check if TDX is enabled in VM
ssh $VM_USER@$NODE_IP << 'EOF'
echo "=== Checking TDX Memory Encryption ==="
sudo dmesg | grep -i "Memory Encryption Features active"

echo -e "\n=== vTPM Devices ==="
ls -la /dev/tpm* 2>/dev/null || echo "No TPM devices found"

echo -e "\n=== TPM Resource Manager Permissions ==="
ls -la /dev/tpmrm0

echo -e "\n=== TSS Group Membership ==="
groups
getent group tss

# Check if correct VM type
echo -e "\n=== VM Size ==="
curl -s -H Metadata:true "http://169.254.169.254/metadata/instance?api-version=2021-02-01" | jq '.compute.vmSize'
EOF

```

**Solutions**:

* Ensure you're using DCedsv5 or DCesv5 series VMs with the confidential VM image
* On Azure TDX CVMs, there is no `/dev/tdx_guest` - attestation uses vTPM (`/dev/tpm0`, `/dev/tpmrm0`)
* Add user to `tss` group: `sudo usermod -aG tss $USER` (requires re-login)
* Verify vTPM is enabled in the VM configuration

### 13.2 Guest Component Connection Failures

**Current Architecture:** The demo uses `grpc-cdh` (Confidential Data Hub) on port 50000 and `ttrpc-attestation-agent` via Unix socket.

```bash
ssh $VM_USER@$NODE_IP << 'EOF'
echo "=== Checking Guest Components ==="

echo "1. grpc-cdh Status (Confidential Data Hub):"
sudo systemctl status grpc-cdh --no-pager | head -10

echo -e "\n2. ttrpc-attestation-agent Status:"
sudo systemctl status ttrpc-attestation-agent --no-pager | head -10

echo -e "\n=== Recent CDH Logs ==="
sudo journalctl -u grpc-cdh --since "10 minutes ago" | tail -30

echo -e "\n=== Recent AA Logs ==="
sudo journalctl -u ttrpc-attestation-agent --since "10 minutes ago" | tail -30

echo -e "\n=== Test CDH Port (keyprovider) ==="
nc -zv 127.0.0.1 50000 && echo "✅ CDH listening on port 50000" || echo "❌ CDH not listening"

echo -e "\n=== Check AA Socket ==="
if [ -S /run/attestation-agent/attestation-agent.sock ]; then
    echo "✅ AA socket exists"
    ls -la /run/attestation-agent/attestation-agent.sock
else
    echo "❌ AA socket not found"
fi

echo -e "\n=== Check offline_fs_kbc Keys (if using offline mode) ==="
if [ -f /etc/aa-offline_fs_kbc-resources.json ]; then
    echo "✅ Offline keys file exists"
    ls -la /etc/aa-offline_fs_kbc-resources.json
else
    echo "⚠️  No offline keys file (using remote attestation?)"
fi

echo -e "\n=== Test KBS Connectivity (if using cc_kbc mode) ==="
# Only test if KBS_PRIVATE_IP is set
if [ -n "$KBS_PRIVATE_IP" ]; then
    curl -v http://$KBS_PRIVATE_IP:8080/kbs/v0/auth 2>&1 | head -20
else
    echo "KBS_PRIVATE_IP not set - skipping KBS connectivity test"
fi
EOF

```

### 13.3 Image Pull Failures

```bash
# Check containerd logs
ssh $VM_USER@$NODE_IP << 'EOF'
echo "=== containerd Logs ==="
sudo journalctl -u containerd --since "10 minutes ago" | grep -E "(decrypt|encrypt|error|fail)" | tail -30

echo -e "\n=== ctd-decoder available? ==="
which ctd-decoder
ctd-decoder --help 2>&1 | head -5

echo -e "\n=== Stream processors config ==="
grep -A 10 "stream_processors" /etc/containerd/config.toml
EOF

```

### 13.4 KBS Key Not Found

```bash
ssh $VM_USER@$KBS_PUBLIC_IP << 'EOF'
echo "=== KBS Repository Contents ==="
ls -laR ~/trustee/kbs/repository/

echo -e "\n=== KBS Logs ==="
cd ~/trustee
docker compose logs --tail 30 | grep -E "(resource|404|error)"
EOF

```

### 13.5 Attestation Agent Build Errors

**Error: `target 'ttrpc-aa' requires the features: 'bin', 'ttrpc'`**

This error occurs when building the Attestation Agent with incorrect feature flags.

```bash
# WRONG - missing required features
cargo build --release --bin ttrpc-aa --no-default-features --features "az-tdx-vtpm"

# CORRECT - for gRPC version (recommended for TCP socket keyprovider)
cargo build --release --bin grpc-aa --no-default-features --features "bin grpc az-tdx-vtpm-attester"

# CORRECT - for TTRPC version (Unix sockets, used by kata-agent)
cargo build --release --bin ttrpc-aa --no-default-features --features "bin ttrpc az-tdx-vtpm-attester"
```

**Which version to use?**

| Binary | Transport | Socket Type | Use Case |
|--------|-----------|-------------|----------|
| `grpc-aa` | gRPC | TCP (`127.0.0.1:50000`) | Standalone AA with containerd/ctd-decoder |
| `ttrpc-aa` | TTRPC | Unix (`/run/confidential-containers/...`) | Kata agent integration |

For this demo (standalone AA with containerd), use `grpc-aa`.

**Alternative: Use the Makefile**

The project Makefile handles features automatically:

```bash
cd guest-components
make build TEE_PLATFORM=az-tdx-vtpm
make install DESTDIR=/usr/local/bin
```

### 13.6 Attestation Agent CLI Errors

**Error: `unexpected argument '--keyprovider_sock' found`**

This error occurs because the guest-components version of AA uses a config file instead of CLI arguments.

```bash
# WRONG - old CLI style (deprecated in guest-components)
attestation-agent --keyprovider_sock 127.0.0.1:50000 --getresource_sock 127.0.0.1:50001

# CORRECT - modern config file approach
attestation-agent -c /etc/attestation-agent/config.toml
```

The config file should contain socket bindings:

```toml
# /etc/attestation-agent/config.toml
[keyprovider]
socket = "127.0.0.1:50000"

[getresource]
socket = "127.0.0.1:50001"

[token_configs.kbs]
url = "http://your-kbs:8080"
```

### 13.7 CDH Not Listening on Keyprovider Port (50000)

**Symptom**: CDH service is running but `nc -z 127.0.0.1 50000` shows "Connection refused"

**Current Architecture (2026)**: This demo uses the modern guest-components architecture:
- **grpc-cdh** - Implements keyprovider gRPC protocol on port 50000
- **ttrpc-aa** - Handles attestation via Unix socket (`/run/attestation-agent/attestation-agent.sock`)

containerd's `ctd-decoder` communicates with grpc-cdh on port 50000 for key unwrapping. CDH then calls ttrpc-aa via the Unix socket when attestation is needed.

**Diagnosis**:
```bash
# Check grpc-cdh status
sudo systemctl status grpc-cdh

# Check grpc-cdh logs
sudo journalctl -u grpc-cdh --since "5 minutes ago"

# Check ttrpc-aa status
sudo systemctl status ttrpc-attestation-agent

# Verify grpc-cdh is listening on port 50000
nc -zv 127.0.0.1 50000

# Verify ttrpc-aa socket exists
ls -la /run/attestation-agent/attestation-agent.sock

# Check grpc-cdh binary
ls -la /usr/local/bin/grpc-cdh

# Check ttrpc-aa binary
ls -la /usr/local/bin/ttrpc-aa
```

**Solutions**:

1. **Restart services**:
   ```bash
   sudo systemctl restart ttrpc-attestation-agent
   sudo systemctl restart grpc-cdh

   # Verify both are running
   sudo systemctl status ttrpc-attestation-agent grpc-cdh --no-pager
   ```

2. **Rebuild with Makefile** (if binaries missing or wrong version):
   ```bash
   cd ~/coco-demo/guest-components
   make build TEE_PLATFORM=az-tdx-vtpm
   sudo make install DESTDIR=/usr/local/bin

   # Restart services after install
   sudo systemctl restart ttrpc-attestation-agent grpc-cdh
   ```

3. **Check configuration**:
   ```bash
   # Check CDH config (if exists)
   cat /etc/confidential-data-hub.json 2>/dev/null || echo "Using default config"

   # Check AA config (for cc_kbc mode with KBS)
   cat /etc/attestation-agent/attestation-agent.conf 2>/dev/null || echo "No AA config (using offline_fs_kbc?)"

   # Check offline keys (for offline_fs_kbc mode)
   ls -la /etc/aa-offline_fs_kbc-resources.json
   ```

4. **Verify containerd configuration**:
   ```bash
   # Check ocicrypt keyprovider config
   cat /etc/containerd/ocicrypt/ocicrypt_keyprovider.conf
   # Should show grpc endpoint: 127.0.0.1:50000

   # Check containerd stream processor
   grep -A 5 "stream_processors" /etc/containerd/config.toml
   ```

**Common Issues**:

| Issue | Cause | Fix |
|-------|-------|-----|
| Port 50000 not listening | grpc-cdh not started | `systemctl restart grpc-cdh` |
| Socket not found | ttrpc-aa not started | `systemctl restart ttrpc-attestation-agent` |
| Services crash on start | Binary mismatch or missing dependencies | Rebuild with correct features |
| "Failed to read file /etc/aa-offline_fs_kbc-keys.json" | Old filename in config | Use `/etc/aa-offline_fs_kbc-resources.json` |

**Note**: Check the [guest-components repository](https://github.com/confidential-containers/guest-components) for current documentation.

### 13.8 Common Error Messages

| Error | Cause | Solution |
| --- | --- | --- |
| `read payload: read configFd: bad file descriptor` | grpc-cdh not listening on 50000 | Restart grpc-cdh service: `systemctl restart grpc-cdh` |
| `missing private key needed for decryption` | grpc-cdh or ttrpc-aa not running | Check services: `systemctl status grpc-cdh ttrpc-attestation-agent` |
| `connection refused 127.0.0.1:50000` | grpc-cdh not listening | Restart service: `systemctl restart grpc-cdh` |
| `attestation failed` | KBS unreachable or policy denied (cc_kbc mode) | Check KBS connectivity and policy.rego |
| `key not found` | Key missing from offline_fs_kbc file or KBS | Add key to `/etc/aa-offline_fs_kbc-resources.json` or KBS repository |
| `Failed to read file /etc/aa-offline_fs_kbc-keys.json` | Old filename in config/logs | Correct file: `/etc/aa-offline_fs_kbc-resources.json` |
| `vTPM device not found` | Wrong VM type or image | Use DCesv5 or DCedsv5 series with confidential VM image |
| `permission denied /dev/tpmrm0` | User not in tss group | Add user: `sudo usermod -aG tss $USER` (re-login required) |
| `TPM access error` | Service lacks TPM permissions | Add `SupplementaryGroups=tss` to systemd service |
| `socket /run/attestation-agent/attestation-agent.sock not found` | ttrpc-aa not running or crashed | Restart: `systemctl restart ttrpc-attestation-agent` |
| `UnwrapKey failed` | Key format mismatch or decryption error | Check key format in offline_fs_kbc file (base64) |
| `no stream processor registered` | containerd not configured for ocicrypt | Add stream processor to `/etc/containerd/config.toml` |
| `image is not encrypted` | Trying to decrypt unencrypted image | Verify image has encrypted layers with `skopeo inspect` |

### 13.9 Debug Checklist

```bash
# Run this on each node to verify setup
ssh $VM_USER@$NODE_IP << 'EOF'
echo "============================================"
echo "    GUEST COMPONENTS VERIFICATION CHECKLIST"
echo "============================================"
echo ""

echo "=== Hardware/Platform ==="
echo -n "1. TDX enabled: "
sudo dmesg | grep -q "Memory Encryption Features active: Intel TDX" && echo "✅ OK" || echo "❌ NOT ENABLED"

echo -n "2. vTPM device (/dev/tpm0): "
[ -c /dev/tpm0 ] && echo "✅ OK" || echo "❌ MISSING"

echo -n "3. TPM resource manager (/dev/tpmrm0): "
[ -c /dev/tpmrm0 ] && echo "✅ OK" || echo "❌ MISSING"

echo ""
echo "=== Core Services ==="
echo -n "4. containerd running: "
systemctl is-active containerd >/dev/null && echo "✅ OK" || echo "❌ NOT RUNNING"

echo -n "5. ttrpc-attestation-agent running: "
systemctl is-active ttrpc-attestation-agent >/dev/null && echo "✅ OK" || echo "❌ NOT RUNNING"

echo -n "6. grpc-cdh running: "
systemctl is-active grpc-cdh >/dev/null && echo "✅ OK" || echo "❌ NOT RUNNING"

echo ""
echo "=== Network/Sockets ==="
echo -n "7. CDH port 50000 listening (keyprovider): "
nc -z 127.0.0.1 50000 2>/dev/null && echo "✅ OK" || echo "❌ NOT LISTENING"

echo -n "8. AA Unix socket exists: "
[ -S /run/attestation-agent/attestation-agent.sock ] && echo "✅ OK" || echo "❌ MISSING"

echo ""
echo "=== Configuration Files ==="
echo -n "9. OCIcrypt keyprovider config: "
[ -f /etc/containerd/ocicrypt/ocicrypt_keyprovider.conf ] && echo "✅ OK" || echo "❌ MISSING"

echo -n "10. containerd stream processor: "
grep -q "ocicrypt.decoder" /etc/containerd/config.toml 2>/dev/null && echo "✅ OK" || echo "❌ NOT CONFIGURED"

echo -n "11. offline_fs_kbc keys (dev mode): "
[ -f /etc/aa-offline_fs_kbc-resources.json ] && echo "✅ OK" || echo "⚠️  Not using offline mode"

echo -n "12. AA config (for cc_kbc mode): "
[ -f /etc/attestation-agent/attestation-agent.conf ] && echo "✅ OK" || echo "⚠️  Not configured (using offline_fs_kbc?)"

echo ""
echo "=== Binaries ==="
echo -n "13. grpc-cdh binary: "
[ -x /usr/local/bin/grpc-cdh ] && echo "✅ OK" || echo "❌ MISSING"

echo -n "14. ttrpc-aa binary: "
[ -x /usr/local/bin/ttrpc-aa ] && echo "✅ OK" || echo "❌ MISSING"

echo ""
echo "=== Permissions ==="
echo -n "15. User in tss group: "
groups | grep -q tss && echo "✅ OK" || echo "⚠️  Not in tss group (may need for manual testing)"

echo -n "16. Services have tss group access: "
grep -q "SupplementaryGroups=tss" /etc/systemd/system/ttrpc-attestation-agent.service 2>/dev/null && echo "✅ OK" || echo "⚠️  Check systemd service files"

echo ""
echo "============================================"
echo ""

# Summary
ISSUES=0
systemctl is-active containerd >/dev/null || ((ISSUES++))
systemctl is-active ttrpc-attestation-agent >/dev/null || ((ISSUES++))
systemctl is-active grpc-cdh >/dev/null || ((ISSUES++))
nc -z 127.0.0.1 50000 2>/dev/null || ((ISSUES++))

if [ $ISSUES -eq 0 ]; then
    echo "✅ ALL CRITICAL CHECKS PASSED"
else
    echo "❌ FOUND $ISSUES CRITICAL ISSUES - Review above output"
fi
EOF

```

---

## References

* [Confidential Containers Documentation](https://confidentialcontainers.org/docs/)
* [Azure Confidential VMs](https://learn.microsoft.com/en-us/azure/confidential-computing/confidential-vm-overview)
* [Intel TDX Documentation](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html)
* [containerd imgcrypt](https://github.com/containerd/imgcrypt)
* [Trustee (KBS)](https://github.com/confidential-containers/trustee)
* [Attestation Agent](https://github.com/confidential-containers/guest-components/tree/main/attestation-agent)
