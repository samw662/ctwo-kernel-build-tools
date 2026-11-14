#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$HOME/Documents/ctwo/kernel/ctwo-workspace"
STOCK="$HOME/Documents/ctwo/STOCK-RETBR"
RELEASES="$HOME/Documents/ctwo/kernel/build/dlkm-releases"
RAMDISK=/mnt/ramdisk
RAM="$RAMDISK/ctwo_sm8635_build"
SRC="$RAM/src"
OUT="$RAM/out"
PKG="$RAM/artifacts"
LOCAL_OUT="$ROOT/out"
CCACHE_DIR="$HOME/.ccache_ctwo"
ENGINE=scripts/build-native-ctwo.sh

usage() {
  echo "Usage: ./build_ram-ctwo.sh {--clean|--dirty|--check}"
}

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

check_paths() {
  local p
  for p in \
    "$ROOT/arch/arm64/configs/ctwo_defconfig" \
    "$ROOT/arch/arm64/configs/ctwo_weary_stars.config" \
    "$ROOT/$ENGINE" \
    "$ROOT/scripts/ctwo-package-boot.py" \
    "$ROOT/scripts/ctwo-package-dlkm.py" \
    "$ROOT/vendor/qcom/opensource/wlan/platform/Kbuild" \
    "$ROOT/vendor/qcom/opensource/wlan/qcacld-3.0/Kbuild" \
    "$WORK/prebuilts/clang/host/linux-x86/clang-r487747c/bin/clang" \
    "$WORK/prebuilts/kernel-build-tools/linux-x86/bin/depmod" \
    "$STOCK/boot.img" "$STOCK/vbmeta.img" \
    "$STOCK/checking/modules/system_dlkm/lib/modules" \
    "$STOCK/checking/modules/vendor_dlkm/lib/modules"; do
    [[ -e "$p" ]] || fail "Missing: $p"
  done

  grep -q 'CTWO_OUT' "$ROOT/$ENGINE" || fail "Apply ctwo-native-ram.patch first"
  grep -q 'CTWO_CCACHE' "$ROOT/$ENGINE" || fail "Engine does not support ccache"
  for p in rsync flock sudo mountpoint findmnt make ccache python3 sha256sum; do
    command -v "$p" >/dev/null || fail "Missing command: $p"
  done
}

activate_bomba() {
  sudo -n sh -c '
    ryzenadj --stapm-limit=85000 --fast-limit=85000 --slow-limit=75000 --apu-slow-limit=75000 --tctl-temp=100 2>/dev/null || true
    for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo performance > "$g"; done
    echo 1 > /sys/devices/system/cpu/cpufreq/boost
    echo performance > /sys/firmware/acpi/platform_profile 2>/dev/null || true
    for q in /sys/block/nvme*/queue/scheduler; do echo none > "$q" 2>/dev/null || true; done
    echo 0 > /proc/sys/kernel/sched_autogroup_enabled
    echo 0 > /proc/sys/kernel/numa_balancing
    echo 128 > /proc/sys/kernel/sched_nr_migrate
    echo 0 > /proc/sys/kernel/sched_migration_cost_ns
    echo 10 > /proc/sys/vm/swappiness
    echo 10 > /proc/sys/vm/dirty_ratio
    echo 5 > /proc/sys/vm/dirty_background_ratio
    nvidia-smi -pl 90 2>/dev/null || true
    nvidia-smi -pm 1 2>/dev/null || true
  ' 2>/dev/null && echo '[ok] BOMBA profile' || echo 'WARN: BOMBA failed (run sudo -v)'
}

activate_sleep() {
  sudo -n sh -c '
    ryzenadj --stapm-limit=25000 --fast-limit=30000 --slow-limit=25000 --apu-slow-limit=25000 --tctl-temp=70 2>/dev/null || true
    for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo powersave > "$g"; done
    echo 0 > /sys/devices/system/cpu/cpufreq/boost
    echo balanced > /sys/firmware/acpi/platform_profile 2>/dev/null || true
    for q in /sys/block/nvme*/queue/scheduler; do echo kyber > "$q" 2>/dev/null || true; done
    echo 1 > /proc/sys/kernel/sched_autogroup_enabled
    echo 1 > /proc/sys/kernel/numa_balancing
    echo 60 > /proc/sys/vm/swappiness
    echo 20 > /proc/sys/vm/dirty_ratio
    echo 10 > /proc/sys/vm/dirty_background_ratio
    nvidia-smi -pl 60 2>/dev/null || true
  ' 2>/dev/null && echo '[ok] SLEEP profile' || true
}

cleanup() {
  local status=$?
  trap - EXIT
  activate_sleep
  if [[ -n "${STAGED:-}" && -d "$STAGED" ]]; then
    rm -rf -- "$STAGED"
  fi
  if [[ -n "${RELEASE_TMP:-}" && -d "$RELEASE_TMP" ]]; then
    rm -rf -- "$RELEASE_TMP"
  fi
  if [[ -n "${LOG:-}" && -s "$LOG" ]]; then
    mkdir -p "$LOCAL_OUT/logs"
    cp "$LOG" "$LOCAL_OUT/logs/$(basename "$LOG")"
  fi
  echo "Build time: $((SECONDS / 60))m $((SECONDS % 60))s"
  exit "$status"
}

next_test() {
  local path name number max=0
  for path in "$RELEASES"/TEST[0-9]*; do
    [[ -d "$path" ]] || continue
    name=${path##*/}
    [[ "$name" =~ ^TEST([0-9]+)$ ]] || continue
    number=$((10#${BASH_REMATCH[1]}))
    (( number > max )) && max=$number
  done
  echo "TEST$((max + 1))"
}

stage_results() {
  local hash boot_dir dlkm_dir candidate
  hash=$(sha256sum "$OUT/arch/arm64/boot/Image")
  hash=${hash%% *}
  boot_dir="$PKG/boot-pairs/$hash"
  dlkm_dir="$PKG/dlkm-releases/$hash/images"

  for candidate in "$boot_dir/boot.img" "$boot_dir/vendor_boot.img" \
    "$dlkm_dir/system_dlkm.img" "$dlkm_dir/vendor_dlkm.img"; do
    [[ -s "$candidate" ]] || fail "Missing packaged image: $candidate"
  done

  STAGED=$(mktemp -d "$LOCAL_OUT/.ctwo-new.XXXXXXXX")
  mkdir -p "$STAGED/images" "$STAGED/modules"
  cp "$boot_dir/boot.img" "$boot_dir/vendor_boot.img" "$STAGED/images/"
  cp "$dlkm_dir/system_dlkm.img" "$dlkm_dir/vendor_dlkm.img" "$STAGED/images/"
  mkdir "$STAGED/manifests"
  cp "$boot_dir/manifest.json" "$STAGED/manifests/boot.json"
  cp "${dlkm_dir%/images}/manifest.json" "$STAGED/manifests/dlkm.json"
  python3 - "$STAGED" "$OUT" "$hash" <<'PY'
import hashlib, json, pathlib, sys
stage, out = map(pathlib.Path, sys.argv[1:3])
image_hash = sys.argv[3]
def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()
boot = json.loads((stage / 'manifests/boot.json').read_text())
dlkm = json.loads((stage / 'manifests/dlkm.json').read_text())
if boot['kernel_sha256'] != image_hash or dlkm['kernel_sha256'] != image_hash:
    raise SystemExit('Packaged images do not match the current kernel')
for field, path in [('vmlinux', out / 'vmlinux'), ('config', out / '.config'),
                    ('module_symvers', out / 'Module.symvers')]:
    if sha(path) != boot[field + '_sha256']:
        raise SystemExit('Boot manifest does not match current ' + field)
if sha(out / 'Module.symvers') != dlkm['module_symvers_sha256'] or sha(out / 'certs/signing_key.x509') != dlkm['certificate_sha256']:
    raise SystemExit('DLKM manifest does not match current symbols or signing certificate')
for name in ('boot.img', 'vendor_boot.img', 'system_dlkm.img', 'vendor_dlkm.img'):
    records = boot['images'] if name in ('boot.img', 'vendor_boot.img') else dlkm['images']
    key = name if name in ('boot.img', 'vendor_boot.img') else name.removesuffix('.img')
    if sha(stage / 'images' / name) != records[key]['sha256']:
        raise SystemExit('Staged image does not match validated manifest: ' + name)
PY
  cp "$OUT/arch/arm64/boot/Image" "$OUT/.config" \
    "$OUT/Module.symvers" "$OUT/modules.order" "$OUT/System.map" \
    "$OUT/modules.builtin" "$OUT/modules.builtin.modinfo" "$STAGED/"
  cp "$OUT/certs/signing_key.x509" "$STAGED/module-signing.x509"

  local latest
  latest=$(find "$OUT/dlkm-staging" -mindepth 1 -maxdepth 1 -type d \
    -name "${hash:0:12}-*" -printf '%T@ %p\n' | sort -rn | head -n 1)
  [[ -n "$latest" ]] || fail 'Missing staged modules'
  cp -a "${latest#* }/system_dlkm" "${latest#* }/vendor_dlkm" "$STAGED/modules/"
  printf '%s\n' 'AVB: vbmeta de desarrollo pendiente de integrar y validar.' \
    'NO FLASHEAR: estas imagenes no son un paquete de despliegue.' > "$STAGED/NO_FLASH.txt"
}

publish() {
  local target previous family_hash
  if [[ "$MODE" == --clean ]]; then
    target="$RELEASES/$(next_test)"
    [[ ! -e "$target" ]] || fail "Already exists: $target"
    family_hash=$(sha256sum "$STAGED/Image")
    family_hash=${family_hash%% *}
    mkdir -p "$LOCAL_OUT/manifests/$family_hash"
    cp -a "$STAGED/manifests/." "$LOCAL_OUT/manifests/$family_hash/"
    RELEASE_TMP="$RELEASES/.$(basename "$target").tmp.$$"
    mkdir "$RELEASE_TMP"
    cp -a "$STAGED/images/." "$RELEASE_TMP/"
    mv -T -n "$RELEASE_TMP" "$target"
    [[ ! -e "$RELEASE_TMP" ]] || fail "Already exists: $target"
    RELEASE_TMP=
    echo "[ok] release: $target"
    echo 'Development images: boot-chain trust and runtime operation remain unverified.'
  fi

  previous="$LOCAL_OUT/.ctwo-old.$$"
  if [[ -e "$LOCAL_OUT/ctwo" ]]; then
    mv -T "$LOCAL_OUT/ctwo" "$previous"
  fi
  mv -T "$STAGED" "$LOCAL_OUT/ctwo"
  [[ ! -e "$previous" ]] || rm -rf -- "$previous"
  echo "[ok] local output: $LOCAL_OUT/ctwo"
}

[[ $# == 1 ]] || { usage; exit 2; }
MODE=$1
case "$MODE" in
  --clean|--dirty|--check) ;;
  -h|--help) usage; exit 0 ;;
  *) usage; exit 2 ;;
esac

SECONDS=0
check_paths
if [[ "$MODE" == --check ]]; then
  echo '[ok] build paths'
  exit 0
fi

mkdir -p "$RELEASES" "$LOCAL_OUT" "$CCACHE_DIR"
exec 9> "$RELEASES/.ctwo-ram-build.lock"
flock -n 9 || fail 'Another ctwo RAM build is running'

trap cleanup EXIT
activate_bomba

if ! mountpoint -q "$RAMDISK"; then
  sudo mkdir -p "$RAMDISK"
  sudo mount -t tmpfs -o size=30G tmpfs "$RAMDISK"
fi
[[ "$(findmnt -n -o FSTYPE --target "$RAMDISK")" == tmpfs ]] || fail "$RAMDISK is not tmpfs"

mkdir -p "$RAM"
READY="$RAM/.ctwo-ready"
if [[ "$MODE" == --dirty ]]; then
  [[ -s "$READY" && -s "$OUT/.config" && -s "$OUT/certs/signing_key.pem" ]] || \
    fail 'No complete RAM build for --dirty. Use --clean.'
  previous_stamp=$(cat "$READY")
else
  rm -rf -- "$OUT"
fi
rm -rf -- "$PKG"
rm -rf -- "$OUT/dlkm-staging" "$OUT/wlan-staging"
rm -f -- "$READY"

rsync -a --delete --exclude='.git/' --exclude='out/' \
  --exclude='*.log' --exclude='*.zip' \
  "$ROOT/" "$SRC/"

config_stamp=$(sha256sum "$SRC/arch/arm64/configs/ctwo_defconfig" \
  "$SRC/arch/arm64/configs/ctwo_weary_stars.config" | sha256sum)
config_stamp=${config_stamp%% *}
if [[ "$MODE" == --dirty ]]; then
  [[ "$previous_stamp" == "$config_stamp" ]] || \
    fail 'Kernel config inputs changed. Use --clean.'
fi

export CCACHE_DIR CCACHE_COMPRESS=1 CCACHE_MAXSIZE=10G
export CCACHE_BASEDIR="$SRC" USE_CCACHE=1
export KBUILD_BUILD_USER=samw662 KBUILD_BUILD_HOST=kerneldust
cores=$(nproc)
JOBS=$((cores * 3))
(( JOBS > 48 )) && JOBS=48
export JOBS

LOG="$RAM/build_ram-ctwo-$(date +%Y%m%d_%H%M%S).log"
echo "CTWO $MODE | $JOBS jobs | RAM: $OUT"
CTWO_WORK="$WORK" CTWO_STOCK="$STOCK" CTWO_OUT="$OUT" CTWO_BUILD="$PKG" \
  CTWO_CCACHE=1 CTWO_ALLOW_CONFIG_UPDATE=1 \
  bash "$SRC/$ENGINE" 2>&1 | tee "$LOG"

stage_results
publish
printf '%s\n' "$config_stamp" > "$READY"
ccache -s || true
