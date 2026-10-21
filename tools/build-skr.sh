#!/usr/bin/env bash
# Builds the AzureAttestSKR helper (Secure Key Release) from Microsoft's sample and installs it in /opt/skr.
#
# The upstream tool releases the key from Key Vault but never prints it. We apply a one-line patch so that,
# when SKR_PRINT_KEY is set, the released private key is written to stdout (PEM). The Node service reads it
# from the pipe and keeps it in memory only - it is never written to disk.
set -euo pipefail

UPSTREAM_REPO="https://github.com/Azure/confidential-computing-cvm-guest-attestation.git"
UPSTREAM_COMMIT="3e863151425e068ae99a6bc53823e968302aee90"
GUEST_ATTEST_DEB="https://packages.microsoft.com/repos/azurecore/pool/main/a/azguestattestation1/azguestattestation1_1.1.2_amd64.deb"
INSTALL_DIR="/opt/skr"
BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y build-essential cmake git curl zlib1g-dev libssl-dev libcurl4-openssl-dev \
  libjsoncpp-dev libboost-all-dev nlohmann-json3-dev libtss2-esys-3.0.2-0

curl -fsSL -o "$BUILD_DIR/azguestattestation.deb" "$GUEST_ATTEST_DEB"
dpkg -i "$BUILD_DIR/azguestattestation.deb" || apt-get install -f -y

git clone --recursive "$UPSTREAM_REPO" "$BUILD_DIR/src"
git -C "$BUILD_DIR/src" checkout --quiet "$UPSTREAM_COMMIT"
git -C "$BUILD_DIR/src" submodule update --init --recursive

APP_DIR="$BUILD_DIR/src/cvm-securekey-release-app"
TARGET="$APP_DIR/AttestationUtil.cpp"

# Insert the print-key hook right after `bool releaseOk = false;` (appears once, in Util::ReleaseKey).
# The upstream files use CRLF line endings; the inserted line is plain text so either style compiles.
PATCH='if (std::getenv("SKR_PRINT_KEY") != nullptr) { if (PEM_write_PrivateKey(stdout, pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1) { throw skr_error(EXIT_CRYPTO_FAIL, "Failed to PEM-encode the released key"); } fflush(stdout); }'
sed -i "0,/bool releaseOk = false;/s//bool releaseOk = false; ${PATCH}/" "$TARGET"
grep -q 'SKR_PRINT_KEY' "$TARGET" || { echo "patch did not apply: upstream layout changed" >&2; exit 1; }

mkdir -p "$APP_DIR/build"
cd "$APP_DIR/build"
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j"$(nproc)"

install -d "$INSTALL_DIR"
install -m 0755 AzureAttestSKR "$INSTALL_DIR/AzureAttestSKR"
echo "AzureAttestSKR installed in $INSTALL_DIR"
