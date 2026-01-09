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
5. [Guest Components (AA + CDH) Configuration](#5-guest-components-aa--cdh-configuration)
6. [containerd Configuration for Encrypted Images](#6-containerd-configuration-for-encrypted-images)
7. [Creating and Pushing Encrypted Images](#7-creating-and-pushing-encrypted-images)
8. [Demonstrating Safety Claims (What Works)](#8-demonstrating-safety-claims-what-works)
9. [Demonstrating What We Lose Without Kata](#9-demonstrating-what-we-lose-without-kata)
10. [Cleanup](#10-cleanup)
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

echo "=== Installing containerd 1.7.x ==="
# IMPORTANT: containerd 2.x has a known bug with stream processors (ctd-decoder)
# that causes "read configFd: bad file descriptor" errors during encrypted image pulls.
# We must use containerd 1.7.x until this is fixed upstream.
sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates curl gnupg lsb-release

CONTAINERD_VERSION="1.7.30"
echo "Installing containerd v${CONTAINERD_VERSION} (NOT 2.x - incompatible with ctd-decoder)"
wget -q https://github.com/containerd/containerd/releases/download/v${CONTAINERD_VERSION}/containerd-${CONTAINERD_VERSION}-linux-amd64.tar.gz
sudo tar -xzf containerd-${CONTAINERD_VERSION}-linux-amd64.tar.gz -C /usr/local
rm containerd-${CONTAINERD_VERSION}-linux-amd64.tar.gz

# Install runc (required by containerd)
RUNC_VERSION="1.2.4"
wget -q https://github.com/opencontainers/runc/releases/download/v${RUNC_VERSION}/runc.amd64
sudo install -m 755 runc.amd64 /usr/local/sbin/runc
rm runc.amd64

# Create systemd service for containerd
sudo tee /etc/systemd/system/containerd.service > /dev/null << 'SYSTEMD'
[Unit]
Description=containerd container runtime
After=network.target local-fs.target

[Service]
ExecStart=/usr/local/bin/containerd
Restart=always
RestartSec=5
Delegate=yes
KillMode=process

[Install]
WantedBy=multi-user.target
SYSTEMD

echo "=== Configuring containerd ==="
sudo mkdir -p /etc/containerd
/usr/local/bin/containerd config default | sudo tee /etc/containerd/config.toml > /dev/null
sudo sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml

sudo systemctl daemon-reload
sudo systemctl restart containerd
sudo systemctl enable containerd
echo "containerd version: $(/usr/local/bin/containerd --version)"

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
mkdir -p ~/coco-demo
scp $VM_USER@$CONTROL_PLANE_PUBLIC_IP:~/.kube/config ~/coco-demo/kubeconfig

# Update the server address to use public IP
sed -i "s|server: https://$CONTROL_PLANE_PRIVATE_IP:6443|server: https://$CONTROL_PLANE_PUBLIC_IP:6443|" ~/coco-demo/kubeconfig

export KUBECONFIG=~/coco-demo/kubeconfig
kubectl get nodes

```

## 5. Guest Components (AA + CDH) Configuration

Configure the Attestation Agent (AA) and Confidential Data Hub (CDH) on all Kubernetes nodes.

> **Note: This demo uses `offline_fs_kbc` mode**
>
> This demo stores encryption keys locally in `/etc/aa-offline_fs_kbc-resources.json` instead of fetching them from a Key Broker Service (KBS) after remote attestation. This simplifies the setup for demonstration purposes but provides **no security guarantees** - the keys are stored in plaintext on disk.
>
> For production deployments, use `cc_kbc` mode with a proper KBS (Intel Trust Authority or Azure MAA) for attestation-gated key release.

**Architecture Note:** The modern CoCo guest-components architecture uses two services working together:
- **Confidential Data Hub (CDH)** - Implements the keyprovider gRPC protocol (port 50000) that containerd/ocicrypt uses for image decryption. In `offline_fs_kbc` mode, CDH reads keys directly from a local file.
- **Attestation Agent (AA)** - Handles TEE attestation via ttrpc protocol (unix socket). In `offline_fs_kbc` mode, AA is still required but attestation is bypassed.

The flow is: `ctd-decoder` (containerd's stream processor) → `grpc-cdh` (port 50000) → local key file (`/etc/aa-offline_fs_kbc-resources.json`).

**Important:**
- CDH must be built with `grpc` feature to listen on TCP port 50000 for the keyprovider protocol
- AA must be built with `ttrpc` feature (required by CDH even in offline mode)
- For Azure TDX, both must be built with `az-tdx-vtpm-attester` feature

### 5.1 Build and Install Guest Components

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

### 5.2 Configure and Start Attestation Agent

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

### 5.3 Configure and Start Confidential Data Hub (CDH)

CDH implements the keyprovider gRPC protocol that containerd uses for image decryption. In `offline_fs_kbc` mode, CDH reads decryption keys from a local file.

```bash
cat > /tmp/configure-cdh.sh << 'SCRIPT'
#!/bin/bash
set -e

echo "=== Creating CDH Configuration for offline_fs_kbc mode ==="
# IMPORTANT: CDH requires .json extension for config file
sudo tee /etc/confidential-data-hub.json > /dev/null << 'EOF'
{
    "socket": "127.0.0.1:50000",
    "kbc": {
        "name": "offline_fs_kbc"
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

### 5.4 Create OCIcrypt Keyprovider Configuration

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

### 5.5 Setup Encryption Keys for offline_fs_kbc

Generate the encryption key locally and deploy it to all Kubernetes nodes. The key will be stored in `/etc/aa-offline_fs_kbc-resources.json` where CDH (already configured for `offline_fs_kbc` mode) will read it.

```bash
# Generate encryption key locally
mkdir -p ~/coco-demo
echo "=== Generating encryption key locally ==="
head -c 32 /dev/urandom > ~/coco-demo/encryption_key

# Create setup script to deploy the key
cat > /tmp/setup-offline-kbc.sh << 'SCRIPT'
#!/bin/bash
set -e

# Read the key and encode it to base64
KEY_BASE64=$(cat /tmp/encryption_key | base64 -w 0)

echo "=== Creating offline_fs_kbc resources file ==="
sudo tee /etc/aa-offline_fs_kbc-resources.json > /dev/null << EOF
{
  "default/image_key/nginx": "$KEY_BASE64"
}
EOF

echo "=== Verifying offline keys file ==="
ls -la /etc/aa-offline_fs_kbc-resources.json
echo "Content (base64 key truncated):"
sudo cat /etc/aa-offline_fs_kbc-resources.json

echo ""
echo "=== Restarting CDH (so it picks up the keys file) ==="
sudo systemctl restart confidential-data-hub
sleep 2
sudo systemctl status confidential-data-hub --no-pager | head -15

echo ""
echo "=== Restarting attestation-agent ==="
sudo systemctl restart attestation-agent
sleep 2
sudo systemctl status attestation-agent --no-pager | head -10
SCRIPT

chmod +x /tmp/setup-offline-kbc.sh

# Apply on all Kubernetes nodes
for IP in $CONTROL_PLANE_PUBLIC_IP $WORKER_PUBLIC_IP; do
    echo ""
    echo "=== Setting up offline_fs_kbc keys on $IP ==="
    scp ~/coco-demo/encryption_key $VM_USER@$IP:/tmp/
    scp /tmp/setup-offline-kbc.sh $VM_USER@$IP:/tmp/
    ssh $VM_USER@$IP 'bash /tmp/setup-offline-kbc.sh'
done

echo ""
echo "=== offline_fs_kbc Keys Deployed ==="
echo "    WARNING: Keys are stored in plaintext on disk - NO security guarantees"
echo ""
```

---

## 6. containerd Configuration for Encrypted Images

### 6.1 Update containerd Configuration

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

### 6.2 Verify Configuration

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

## 7. Creating and Pushing Encrypted Images

### 7.1 Set Up Local Encryption Environment

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

### 7.2 Encrypt and Push Image

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

### 7.3 Create a Secret Application Image

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

## 8. Demonstrating Safety Claims (What Works)

### 8.1 Deploy Encrypted Workload

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

### 8.2 Verify Decryption Worked

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

### 8.3 Deploy Secret Application

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

---

## 9. Demonstrating What We Lose Without Kata

This section demonstrates the security properties that are **LOST** when not using Kata runtime with per-pod TEE isolation.

### 9.1 Shared TEE Boundary - Container Escape Demo

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

### 9.2 No Per-Pod Attestation Identity

**Risk**: All pods share the same CVM's attestation identity. KBS cannot distinguish between pods.

```bash
echo "=== DEMONSTRATING SHARED ATTESTATION IDENTITY ==="

# Install tpm2-tools in the attacker pod to read TPM PCR values
kubectl exec attacker-pod -- bash -c 'apt-get update && apt-get install -y tpm2-tools >/dev/null 2>&1'

# On Azure TDX, attestation uses vTPM - all pods share the same vTPM identity
# Get TPM PCR values from two different pods (via host access)
kubectl exec attacker-pod -- bash -c '
echo "Reading TPM PCR values from host..."
if [ -e /host/dev/tpmrm0 ]; then
    # All pods on this CVM share the same TPM identity
    tpm2_pcrread -T "device:/host/dev/tpmrm0" sha256:0,1,2,3
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

### 9.3 No Per-Pod Key Policies

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

### 9.4 No Agent Policy Enforcement (kubectl exec unrestricted)

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

### 9.5 Shared Namespace Risks

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

### 9.6 Memory Access Across Containers

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

## 10. Cleanup

### 10.1 Delete Kubernetes Resources

```bash
kubectl delete pod --all --force --grace-period=0

```

### 10.2 Delete Azure Resources

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

### 10.3 Local Cleanup

```bash
rm -rf ~/coco-demo
rm -f ~/.kube/config-coco-demo

```
