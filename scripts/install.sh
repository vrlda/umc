#!/bin/sh

set -eu

readonly BIN_NAME="openmeshd"
readonly SERVICE_NAME="${OPENMESH_SERVICE_NAME:-openmesh}"
readonly CONFIG_PATH="${OPENMESH_CONFIG_PATH:-/etc/openmesh/config.json}"
readonly DATA_DIR="${OPENMESH_DATA_DIR:-/var/lib/openmesh}"
readonly BIN_PATH="${OPENMESH_BIN_PATH:-/usr/bin/${BIN_NAME}}"
readonly SYSTEMD_UNIT_PATH="${OPENMESH_SYSTEMD_UNIT_PATH:-/etc/systemd/system/${SERVICE_NAME}.service}"
readonly OPENRC_SERVICE_PATH="${OPENMESH_OPENRC_SERVICE_PATH:-/etc/init.d/${SERVICE_NAME}}"
readonly OS_RELEASE_PATH="${OPENMESH_OS_RELEASE_PATH:-/etc/os-release}"
readonly RELEASE_VERSION="${OPENMESH_RELEASE_VERSION:-latest}"
readonly GITHUB_REPOSITORY_DEFAULT="__OPENMESH_GITHUB_REPOSITORY__"
readonly GITHUB_REPOSITORY="${OPENMESH_GITHUB_REPOSITORY:-${GITHUB_REPOSITORY_DEFAULT}}"
readonly OPENMESH_USER="${OPENMESH_USER:-openmesh}"
readonly OPENMESH_GROUP="${OPENMESH_GROUP:-${OPENMESH_USER}}"
readonly ALLOW_UNPRIVILEGED="${OPENMESH_ALLOW_UNPRIVILEGED:-0}"
readonly SKIP_SERVICE_START="${OPENMESH_SKIP_SERVICE_START:-0}"
readonly NONINTERACTIVE_KIND="${OPENMESH_NODE_KIND:-}"
readonly NONINTERACTIVE_BANDWIDTH="${OPENMESH_BANDWIDTH_MBPS:-}"
readonly OVERRIDE_BINARY_URL="${OPENMESH_BINARY_URL:-}"
readonly OVERRIDE_CHECKSUM_URL="${OPENMESH_CHECKSUM_URL:-}"
readonly OVERRIDE_BOOTSTRAP_MANIFEST_URL="${OPENMESH_BOOTSTRAP_MANIFEST_URL:-}"

AS_ROOT=""
ARCH=""
OS_FAMILY=""
SERVICE_MANAGER=""
INSTALL_MODE=""
BANDWIDTH_LIMIT=""
TMP_DIR=""
OPENRC_RUN_AS_USER="0"

cleanup() {
  if [ -n "${TMP_DIR}" ] && [ -d "${TMP_DIR}" ]; then
    rm -rf "${TMP_DIR}"
  fi
}

trap cleanup EXIT INT TERM

log() {
  printf '[openmesh] %s\n' "$*"
}

die() {
  printf '[openmesh] Error: %s\n' "$*" >&2
  exit 1
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

as_root() {
  if [ -n "${AS_ROOT}" ]; then
    "${AS_ROOT}" "$@"
    return
  fi
  "$@"
}

init_privilege_helper() {
  if [ "${ALLOW_UNPRIVILEGED}" = "1" ] || [ "$(id -u)" -eq 0 ]; then
    AS_ROOT=""
    return
  fi

  have_cmd sudo || die "sudo is required when running without root privileges"
  AS_ROOT="sudo"
}

download_to() {
  url="$1"
  output_path="$2"

  if have_cmd curl; then
    curl -fsSL "${url}" -o "${output_path}"
    return
  fi
  if have_cmd wget; then
    wget -qO "${output_path}" "${url}"
    return
  fi

  die "curl or wget is required to download release artifacts"
}

sha256_file() {
  path="$1"

  if have_cmd sha256sum; then
    sha256sum "${path}" | awk '{print $1}'
    return
  fi
  if have_cmd shasum; then
    shasum -a 256 "${path}" | awk '{print $1}'
    return
  fi
  if have_cmd openssl; then
    openssl dgst -sha256 "${path}" | awk '{print $NF}'
    return
  fi

  die "sha256sum, shasum, or openssl is required to verify checksums"
}

prompt_with_default() {
  message="$1"
  default_value="$2"
  response=""

  if [ -r /dev/tty ]; then
    printf '%s' "${message}" > /dev/tty
    IFS= read -r response < /dev/tty || response=""
  fi

  if [ -z "${response}" ]; then
    response="${default_value}"
  fi

  printf '%s' "${response}"
}

detect_os() {
  [ -r "${OS_RELEASE_PATH}" ] || die "unable to read ${OS_RELEASE_PATH}"

  id_like=""
  distro_id=""

  # shellcheck disable=SC1090
  . "${OS_RELEASE_PATH}"
  distro_id="${ID:-}"
  id_like="${ID_LIKE:-}"

  case "${distro_id} ${id_like}" in
    *alpine*)
      OS_FAMILY="alpine"
      SERVICE_MANAGER="openrc"
      ;;
    *ubuntu*|*debian*)
      OS_FAMILY="debian"
      SERVICE_MANAGER="systemd"
      ;;
    *centos*|*rhel*|*rocky*|*almalinux*|*fedora*)
      OS_FAMILY="redhat"
      SERVICE_MANAGER="systemd"
      ;;
    *)
      die "unsupported Linux distribution: ${distro_id:-unknown}"
      ;;
  esac

  if [ "${SERVICE_MANAGER}" = "systemd" ] && ! have_cmd systemctl; then
    die "systemctl is required on ${OS_FAMILY}-based systems"
  fi
  if [ "${SERVICE_MANAGER}" = "openrc" ]; then
    have_cmd rc-service || die "rc-service is required on Alpine/OpenRC systems"
    have_cmd rc-update || die "rc-update is required on Alpine/OpenRC systems"
  fi
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64)
      ARCH="amd64"
      ;;
    aarch64|arm64)
      ARCH="arm64"
      ;;
    *)
      die "unsupported CPU architecture: $(uname -m)"
      ;;
  esac
}

resolve_node_kind() {
  answer="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | tr -d ' ')"

  case "${answer}" in
    relay)
      INSTALL_MODE="relay"
      ;;
    exit|full|relay+exit|relay-exit)
      INSTALL_MODE="full"
      ;;
    *)
      die "node type must be relay or exit"
      ;;
  esac
}

prompt_node_kind() {
  if [ -n "${NONINTERACTIVE_KIND}" ]; then
    resolve_node_kind "${NONINTERACTIVE_KIND}"
    return
  fi

  resolve_node_kind "$(prompt_with_default 'Relay only, or relay + exit? [relay/exit] ' 'exit')"
}

prompt_bandwidth_limit() {
  input="${NONINTERACTIVE_BANDWIDTH}"

  if [ -z "${input}" ]; then
    input="$(prompt_with_default 'Bandwidth limit in Mbps? [default: 10] ' '10')"
  fi

  case "${input}" in
    ''|*[!0-9]*)
      die "bandwidth must be a non-negative integer"
      ;;
  esac
  BANDWIDTH_LIMIT="${input}"
}

artifact_url() {
  if [ -n "${OVERRIDE_BINARY_URL}" ]; then
    printf '%s' "${OVERRIDE_BINARY_URL}"
    return
  fi
  require_github_repository
  printf '%s/%s-linux-%s' "$(github_release_base_url)" "${BIN_NAME}" "${ARCH}"
}

checksum_url() {
  if [ -n "${OVERRIDE_CHECKSUM_URL}" ]; then
    printf '%s' "${OVERRIDE_CHECKSUM_URL}"
    return
  fi
  printf '%s.sha256' "$(artifact_url)"
}

bootstrap_manifest_url() {
  if [ -n "${OVERRIDE_BOOTSTRAP_MANIFEST_URL}" ]; then
    printf '%s' "${OVERRIDE_BOOTSTRAP_MANIFEST_URL}"
    return
  fi
  require_github_repository
  printf '%s/bootstrap-peers.json' "$(github_release_base_url)"
}

github_release_base_url() {
  if [ "${RELEASE_VERSION}" = "latest" ]; then
    printf 'https://github.com/%s/releases/latest/download' "${GITHUB_REPOSITORY}"
    return
  fi
  printf 'https://github.com/%s/releases/download/%s' "${GITHUB_REPOSITORY}" "${RELEASE_VERSION}"
}

require_github_repository() {
  if [ -z "${GITHUB_REPOSITORY}" ] || [ "${GITHUB_REPOSITORY}" = "${GITHUB_REPOSITORY_DEFAULT}" ]; then
    die "OPENMESH_GITHUB_REPOSITORY is not set. Use the rendered release installer or export OPENMESH_GITHUB_REPOSITORY=owner/repo."
  fi
}

url_basename() {
  url="$1"
  url="${url%%\?*}"
  printf '%s' "${url##*/}"
}

fetch_release_artifact() {
  binary_url="$1"
  hash_url="$2"
  artifact_path="$3"
  checksum_path="$4"

  log "Downloading ${BIN_NAME} for ${OS_FAMILY}/${ARCH}"
  download_to "${binary_url}" "${artifact_path}"
  download_to "${hash_url}" "${checksum_path}"

  expected="$(tr -d '\r' < "${checksum_path}" | awk 'NF {print $1; exit}')"
  [ -n "${expected}" ] || die "checksum file at ${hash_url} did not contain a SHA-256 digest"

  actual="$(sha256_file "${artifact_path}")"
  [ "${expected}" = "${actual}" ] || die "checksum verification failed for ${binary_url}"
}

extract_binary_if_needed() {
  artifact_path="$1"
  extracted_dir="$2"
  candidate=""

  mkdir -p "${extracted_dir}"
  case "${artifact_path}" in
    *.tar.gz|*.tgz)
      have_cmd tar || die "tar is required to extract ${artifact_path}"
      tar -xzf "${artifact_path}" -C "${extracted_dir}"
      candidate="$(find "${extracted_dir}" -type f -name "${BIN_NAME}" | head -n 1)"
      ;;
    *)
      candidate="${artifact_path}"
      ;;
  esac

  [ -n "${candidate}" ] && [ -f "${candidate}" ] || die "release artifact did not contain ${BIN_NAME}"
  chmod +x "${candidate}"
  printf '%s' "${candidate}"
}

nologin_shell() {
  shell_path=""
  for shell_path in /usr/sbin/nologin /sbin/nologin /bin/false; do
    if [ -x "${shell_path}" ]; then
      printf '%s' "${shell_path}"
      return
    fi
  done
  printf '/bin/false'
}

group_exists() {
  if have_cmd getent; then
    getent group "$1" >/dev/null 2>&1
    return
  fi
  grep -q "^$1:" /etc/group 2>/dev/null
}

ensure_service_user() {
  if id -u "${OPENMESH_USER}" >/dev/null 2>&1; then
    return
  fi

  shell_path="$(nologin_shell)"

  case "${OS_FAMILY}" in
    alpine)
      if ! group_exists "${OPENMESH_GROUP}"; then
        as_root addgroup -S "${OPENMESH_GROUP}"
      fi
      as_root adduser -S -D -H -h "${DATA_DIR}" -s "${shell_path}" -G "${OPENMESH_GROUP}" "${OPENMESH_USER}"
      ;;
    *)
      if ! group_exists "${OPENMESH_GROUP}"; then
        as_root groupadd --system "${OPENMESH_GROUP}"
      fi
      as_root useradd \
        --system \
        --home-dir "${DATA_DIR}" \
        --create-home \
        --shell "${shell_path}" \
        --gid "${OPENMESH_GROUP}" \
        "${OPENMESH_USER}"
      ;;
  esac
}

prepare_install_paths() {
  as_root install -d -m 0755 "$(dirname "${BIN_PATH}")"
  as_root install -d -m 0755 "$(dirname "${CONFIG_PATH}")"
  as_root install -d -m 0755 "${DATA_DIR}"

  case "${SERVICE_MANAGER}" in
    systemd)
      as_root install -d -m 0755 "$(dirname "${SYSTEMD_UNIT_PATH}")"
      ;;
    openrc)
      as_root install -d -m 0755 "$(dirname "${OPENRC_SERVICE_PATH}")"
      ;;
  esac
}

install_binary() {
  source_path="$1"

  log "Installing ${BIN_NAME} to ${BIN_PATH}"
  as_root install -m 0755 "${source_path}" "${BIN_PATH}"
}

maybe_set_binary_capability() {
  if ! have_cmd setcap; then
    return
  fi

  if as_root setcap cap_net_bind_service=+ep "${BIN_PATH}" >/dev/null 2>&1; then
    OPENRC_RUN_AS_USER="1"
    return
  fi

  log "setcap was unavailable or failed; continuing without file capabilities"
}

write_config() {
  temp_path="${TMP_DIR}/config.json"
  bootstrap_url="$(bootstrap_manifest_url)"

  cat > "${temp_path}" <<EOF
{
  "mode": "${INSTALL_MODE}",
  "hops": 2,
  "bandwidth_limit_mbps": ${BANDWIDTH_LIMIT},
  "exit_policy": {
    "ports": [443],
    "blocklist": "default"
  },
  "data_dir": "${DATA_DIR}",
  "log_level": "warn",
  "bootstrap_manifest_urls": [
    "${bootstrap_url}"
  ]
}
EOF

  as_root install -m 0644 "${temp_path}" "${CONFIG_PATH}"
  if id -u "${OPENMESH_USER}" >/dev/null 2>&1; then
    as_root chown "${OPENMESH_USER}:${OPENMESH_GROUP}" "${DATA_DIR}"
  fi
}

write_systemd_unit() {
  temp_path="${TMP_DIR}/openmesh.service"

  cat > "${temp_path}" <<EOF
[Unit]
Description=OpenMesh Node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${BIN_PATH} --config ${CONFIG_PATH} start
Restart=always
RestartSec=5
User=${OPENMESH_USER}
Group=${OPENMESH_GROUP}
WorkingDirectory=${DATA_DIR}
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
EOF

  as_root install -m 0644 "${temp_path}" "${SYSTEMD_UNIT_PATH}"
}

write_openrc_service() {
  temp_path="${TMP_DIR}/openmesh.openrc"
  command_user_line=""

  if [ "${OPENRC_RUN_AS_USER}" = "1" ]; then
    command_user_line="command_user=\"${OPENMESH_USER}:${OPENMESH_GROUP}\""
  fi

  cat > "${temp_path}" <<EOF
#!/sbin/openrc-run

description="OpenMesh Node"
command="${BIN_PATH}"
command_args="--config ${CONFIG_PATH} start"
command_background="yes"
pidfile="/run/${SERVICE_NAME}.pid"
retry="SIGTERM/15/SIGKILL/5"
${command_user_line}

depend() {
  need net
  after firewall
}
EOF

  as_root install -m 0755 "${temp_path}" "${OPENRC_SERVICE_PATH}"
}

install_service() {
  case "${SERVICE_MANAGER}" in
    systemd)
      write_systemd_unit
      ;;
    openrc)
      write_openrc_service
      ;;
  esac
}

enable_and_start_service() {
  if [ "${SKIP_SERVICE_START}" = "1" ]; then
    log "Skipping service enable/start because OPENMESH_SKIP_SERVICE_START=1"
    return
  fi

  log "Enabling and starting ${SERVICE_NAME}"
  case "${SERVICE_MANAGER}" in
    systemd)
      as_root systemctl daemon-reload
      as_root systemctl enable --now "${SERVICE_NAME}.service"
      ;;
    openrc)
      as_root rc-update add "${SERVICE_NAME}" default >/dev/null
      if ! as_root rc-service "${SERVICE_NAME}" restart >/dev/null 2>&1; then
        as_root rc-service "${SERVICE_NAME}" start >/dev/null
      fi
      ;;
  esac
}

show_service_debug() {
  case "${SERVICE_MANAGER}" in
    systemd)
      as_root systemctl --no-pager --lines=20 status "${SERVICE_NAME}.service" || true
      ;;
    openrc)
      as_root rc-service "${SERVICE_NAME}" status || true
      ;;
  esac
}

wait_for_node_id() {
  if [ "${SKIP_SERVICE_START}" = "1" ]; then
    printf '%s' "${OPENMESH_NODE_ID:-skipped}"
    return
  fi

  attempt=""
  status_output=""
  node_id=""

  for attempt in $(seq 1 30); do
    status_output="$("${BIN_PATH}" --config "${CONFIG_PATH}" status 2>/dev/null || true)"
    if [ -n "${status_output}" ]; then
      node_id="$(printf '%s\n' "${status_output}" | awk -F': ' '/^Node ID:/ {print $2; exit}')"
      if [ -n "${node_id}" ]; then
        printf '%s' "${node_id}"
        return
      fi
    fi
    sleep 1
  done

  show_service_debug
  die "service started but ${BIN_NAME} did not report a node ID within 30 seconds"
}

main() {
  umask 022
  TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/openmesh-install.XXXXXX")"

  init_privilege_helper
  detect_os
  detect_arch
  prompt_node_kind
  prompt_bandwidth_limit

  binary_url="$(artifact_url)"
  checksum_download_url="$(checksum_url)"
  artifact_path="${TMP_DIR}/$(url_basename "${binary_url}")"
  checksum_path="${TMP_DIR}/$(url_basename "${checksum_download_url}")"

  fetch_release_artifact "${binary_url}" "${checksum_download_url}" "${artifact_path}" "${checksum_path}"
  binary_source="$(extract_binary_if_needed "${artifact_path}" "${TMP_DIR}/extract")"

  prepare_install_paths
  ensure_service_user
  install_binary "${binary_source}"
  maybe_set_binary_capability
  write_config
  install_service
  enable_and_start_service
  node_id="$(wait_for_node_id)"

  printf 'OpenMesh node is running. Node ID: %s\n' "${node_id}"
}

main "$@"
