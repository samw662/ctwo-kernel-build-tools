#!/usr/bin/env bash
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${CTWO_WORK:-$HOME/Documents/ctwo/kernel/ctwo-workspace}"
BUILD="${CTWO_BUILD:-$HOME/Documents/ctwo/kernel/build}"
OUT="${CTWO_OUT:-$BUILD/native-sm8635}"
SIGNING_KEY="$OUT/certs/signing_key.pem"
SIGNING_CERT="$OUT/certs/signing_key.x509"
STOCK="${CTWO_STOCK:-$HOME/Documents/ctwo/STOCK-RETBR}"
CLANG="$WORK/prebuilts/clang/host/linux-x86/clang-r487747c/bin"
TOOLS="$WORK/prebuilts/kernel-build-tools/linux-x86/bin"
DTC="$TOOLS/dtc"
LLVM_STRIP="$CLANG/llvm-strip"
LLVM_READELF="$CLANG/llvm-readelf"
DEPMOD="$TOOLS/depmod"
WLAN_PLATFORM=vendor/qcom/opensource/wlan/platform
WLAN_DRIVER=vendor/qcom/opensource/wlan/qcacld-3.0
EXPECTED_RELEASE='6.1.128—WearyStars⭐'
EXPECTED_CONFIG_SHA256=f742c16d09ae72ec2a4caff6cebbe1bfc4a64322faf6e1ac00cd3fd4542a7449
WLAN_PROFILE=${CTWO_WLAN_PROFILE:-external}
case "$WLAN_PROFILE" in external|native) ;; *) echo "Invalid CTWO_WLAN_PROFILE: $WLAN_PROFILE" >&2; exit 1 ;; esac
EXPECTED_STOCK_BOOT_SHA256=5a764e10fd6cc9afd1c9661b1dbabd72b29bd128c0c192b41046fc591e4b94df
EXPECTED_STOCK_VBMETA_SHA256=6390f95382c24a8d881c155df72adabf114e1158fc84075d2170630b8e63d026
PARTITION_SIZE=100663296
STOCK_BOOT_DIGEST=1b57aed3216f764b1f0cb9f1d897317eb22fbe846b98b705d25118a52aa633ed

for tool in clang ld.lld llvm-ar llvm-objcopy; do
  [[ -x "$CLANG/$tool" ]] || { echo "Missing pinned tool: $CLANG/$tool" >&2; exit 1; }
done
for tool in "$LLVM_STRIP" "$LLVM_READELF" "$DEPMOD"; do
  [[ -x "$tool" ]] || { echo "Missing pinned module tool: $tool" >&2; exit 1; }
done
[[ -x "$DTC" ]] || { echo "Missing pinned DTC: $DTC" >&2; exit 1; }
for tool in make mkbootimg unpack_bootimg avbtool sha256sum modinfo modprobe openssl pkg-config python3; do
  command -v "$tool" >/dev/null || { echo "Missing required tool: $tool" >&2; exit 1; }
done

export PKG_CONFIG_PATH="/usr/lib/openssl-3/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
OPENSSL_VERSION=$(pkg-config --modversion libcrypto) || { echo 'OpenSSL 3 pkg-config metadata is unavailable' >&2; exit 1; }
OPENSSL_CFLAGS=$(pkg-config --cflags libcrypto)
OPENSSL_LIBS=$(pkg-config --libs libcrypto)
[[ "$OPENSSL_VERSION" == 3.* && " $OPENSSL_CFLAGS " == *' -I/usr/include/openssl-3 '* &&
   " $OPENSSL_LIBS " == *' -L/usr/lib/openssl-3 '* && " $OPENSSL_LIBS " == *' -lcrypto '* ]] || {
  echo "OpenSSL 3 host flags required; found $OPENSSL_VERSION: $OPENSSL_CFLAGS $OPENSSL_LIBS" >&2
  exit 1
}

export PATH="$CLANG:$TOOLS:$PATH"
unset KCONFIG_CONFIG
MAKE=(make -C "$SRC" "O=$OUT" ARCH=arm64 "LLVM=$CLANG/" LLVM_IAS=1 \
  KCFLAGS=-D__ANDROID_COMMON_KERNEL__ "DTC=$DTC" LOCALVERSION=)
if [[ "${CTWO_CCACHE:-0}" == 1 ]]; then
  command -v ccache >/dev/null || { echo "Missing ccache" >&2; exit 1; }
  MAKE+=("CC=ccache $CLANG/clang")
fi

mkdir -p "$OUT" "$BUILD"
SIGNING_KEY_SHA256=
SIGNING_CERT_SHA256=
if [[ -e "$SIGNING_KEY" || -e "$SIGNING_CERT" ]]; then
  [[ -s "$SIGNING_KEY" && -s "$SIGNING_CERT" ]] || { echo 'Incomplete module signing material' >&2; exit 1; }
  SIGNING_KEY_SHA256=$(sha256sum "$SIGNING_KEY" | cut -d ' ' -f1)
  SIGNING_CERT_SHA256=$(sha256sum "$SIGNING_CERT" | cut -d ' ' -f1)
fi
if [[ -s "$OUT/.config" && -z "$SIGNING_KEY_SHA256" ]]; then
  echo 'Existing build has no signing key; refusing an unexpected key regeneration' >&2
  exit 1
fi
if [[ ! -s "$OUT/.config" ]]; then
  "${MAKE[@]}" ctwo_defconfig 2>&1 | tee "$OUT/config.log"
  (
    cd "$OUT"
    "$SRC/scripts/kconfig/merge_config.sh" -m -O "$OUT" "$OUT/.config" \
      "$SRC/arch/arm64/configs/ctwo_weary_stars.config"
  ) 2>&1 | tee -a "$OUT/config.log"
  if [[ "$WLAN_PROFILE" == native ]]; then
    "$SRC/scripts/config" --file "$OUT/.config" --module CTWO_WLAN_NATIVE
  fi
  "${MAKE[@]}" olddefconfig 2>&1 | tee -a "$OUT/config.log"
fi
"${MAKE[@]}" syncconfig 2>&1 | tee -a "$OUT/config.log"
if [[ "$WLAN_PROFILE" == native ]]; then
  grep -Fxq 'CONFIG_CTWO_WLAN_NATIVE=m' "$OUT/.config" || { echo 'Native WLAN profile is unavailable or does not match the existing config' >&2; exit 1; }
else
  ! grep -Eq '^CONFIG_CTWO_WLAN_NATIVE=[ym]$' "$OUT/.config" || { echo 'Existing config uses native WLAN; use a clean build to switch profiles' >&2; exit 1; }
fi
grep -Fxq 'CONFIG_LOCALVERSION="—WearyStars⭐"' "$OUT/.config" || { echo 'Wrong CONFIG_LOCALVERSION' >&2; exit 1; }
grep -Fxq '# CONFIG_LOCALVERSION_AUTO is not set' "$OUT/.config" || { echo 'CONFIG_LOCALVERSION_AUTO must be disabled' >&2; exit 1; }
grep -Fxq 'CONFIG_MODULE_SIG_HASH="sha1"' "$OUT/.config" || { echo 'Unexpected module signature hash' >&2; exit 1; }
grep -Fxq '# CONFIG_MODULE_SIG_ALL is not set' "$OUT/.config" || { echo 'Automatic module signing must be disabled' >&2; exit 1; }
for setting in CONFIG_ARCH_CLIFFS=y CONFIG_ARCH_PINEAPPLE=y CONFIG_CTWO_DTB=y \
  CONFIG_MODVERSIONS=y CONFIG_MODULE_SIG=y CONFIG_MODULE_SIG_PROTECT=y \
  CONFIG_RFKILL=m CONFIG_CFG80211=m; do
  grep -Fxq "$setting" "$OUT/.config" || { echo "Missing $setting" >&2; exit 1; }
done
CONFIG_SHA256=$(sha256sum "$OUT/.config" | cut -d ' ' -f1)
if [[ "${CTWO_ALLOW_CONFIG_UPDATE:-0}" != 1 ]]; then
  [[ "$CONFIG_SHA256" == "$EXPECTED_CONFIG_SHA256" ]] || { echo "Unexpected effective config SHA-256: $CONFIG_SHA256" >&2; exit 1; }
fi

RELEASE=$("${MAKE[@]}" -s kernelrelease 2>"$OUT/kernelrelease.log")
[[ "$RELEASE" == "$EXPECTED_RELEASE" ]] || { echo "Unexpected kernel release: $RELEASE" >&2; exit 1; }
IMAGE="$OUT/arch/arm64/boot/Image"
"${MAKE[@]}" -j"${JOBS:-$(nproc)}" Image modules 2>&1 | tee -a "$OUT/Image-modules-build.log"
[[ "$(sha256sum "$OUT/.config" | cut -d ' ' -f1)" == "$CONFIG_SHA256" ]] || { echo 'Kernel configuration changed during build' >&2; exit 1; }
for artifact in "$IMAGE" "$OUT/Module.symvers" "$OUT/modules.order" \
  "$OUT/net/rfkill/rfkill.ko" "$OUT/net/wireless/cfg80211.ko" \
  "$SIGNING_KEY" "$SIGNING_CERT"; do
  [[ -s "$artifact" ]] || { echo "Missing build artifact: $artifact" >&2; exit 1; }
done
grep -Fxq 'net/rfkill/rfkill.ko' "$OUT/modules.order" || { echo 'rfkill.ko missing from modules.order' >&2; exit 1; }
grep -Fxq 'net/wireless/cfg80211.ko' "$OUT/modules.order" || { echo 'cfg80211.ko missing from modules.order' >&2; exit 1; }
if [[ -n "$SIGNING_KEY_SHA256" ]]; then
  [[ "$(sha256sum "$SIGNING_KEY" | cut -d ' ' -f1)" == "$SIGNING_KEY_SHA256" ]] || { echo 'Module signing key changed' >&2; exit 1; }
  [[ "$(sha256sum "$SIGNING_CERT" | cut -d ' ' -f1)" == "$SIGNING_CERT_SHA256" ]] || { echo 'Module signing certificate changed' >&2; exit 1; }
fi
IMAGE_SHA256=$(sha256sum "$IMAGE" | cut -d ' ' -f1)
SYMVERS_SHA256=$(sha256sum "$OUT/Module.symvers" | cut -d ' ' -f1)
SIGNING_KEY_SHA256=$(sha256sum "$SIGNING_KEY" | cut -d ' ' -f1)
SIGNING_CERT_SHA256=$(sha256sum "$SIGNING_CERT" | cut -d ' ' -f1)

# Build CNSS before Kiwi.
for source in "$SRC/$WLAN_PLATFORM/Kbuild" "$SRC/$WLAN_DRIVER/Kbuild" \
  "$SRC/$WLAN_DRIVER/configs/pineapple_gki_kiwi-v2_defconfig" \
  "$SRC/vendor/qcom/opensource/wlan/fw-api" "$SRC/$WLAN_DRIVER/cmn"; do
  [[ -e "$source" ]] || { echo "Missing WLAN source: $source" >&2; exit 1; }
done
if [[ "$WLAN_PROFILE" == external ]]; then
  "${MAKE[@]}" -j"${JOBS:-$(nproc)}" "M=$WLAN_PLATFORM" \
  "WLAN_PLATFORM_ROOT=$SRC/$WLAN_PLATFORM" \
  CONFIG_CNSS_OUT_OF_TREE=y CONFIG_CNSS2=m CONFIG_CNSS2_QMI=y \
  CONFIG_CNSS_QMI_SVC=m CONFIG_CNSS_PLAT_IPC_QMI_SVC=m \
  CONFIG_CNSS_UTILS=m CONFIG_CNSS_GENL=m CONFIG_WCNSS_MEM_PRE_ALLOC=m \
  CONFIG_BUS_AUTO_SUSPEND=y \
  CONFIG_CNSS_HW_SECURE_DISABLE=y CONFIG_CNSS_HW_SECURE_SMEM=y \
  CONFIG_CNSS2_SSR_DRIVER_DUMP=y CONFIG_CNSS2_SMMU_DB_SUPPORT=y \
  modules 2>&1 | tee -a "$OUT/WLAN-modules-build.log"
  WLAN_SYMVERS="$OUT/$WLAN_PLATFORM/Module.symvers"
  [[ -s "$WLAN_SYMVERS" ]] || { echo "Missing WLAN platform symbols: $WLAN_SYMVERS" >&2; exit 1; }

  "${MAKE[@]}" -j"${JOBS:-$(nproc)}" "M=$WLAN_DRIVER" \
  "WLAN_ROOT=$SRC/$WLAN_DRIVER" \
  "WLAN_FW_API=$SRC/vendor/qcom/opensource/wlan/fw-api" \
  "WLAN_PLATFORM_INC=$SRC/$WLAN_PLATFORM/inc" \
  "WLAN_PROFILE=pineapple_gki_kiwi-v2" \
  "KBUILD_EXTRA_SYMBOLS=$WLAN_SYMVERS" \
  MODNAME=qca_cld3_kiwi_v2 DEVNAME=kiwi_v2 DYNAMIC_SINGLE_CHIP=kiwi_v2 \
  BOARD_PLATFORM=pineapple CONFIG_QCA_CLD_WLAN=m \
  CONFIG_QCA_WIFI_ISOC=0 CONFIG_QCA_WIFI_2_0=1 \
  CONFIG_CNSS2=m CONFIG_CNSS2_MODULE=y CONFIG_CNSS_OUT_OF_TREE=y \
  modules 2>&1 | tee -a "$OUT/WLAN-modules-build.log"
else
  WLAN_SYMVERS="$OUT/Module.symvers"
fi

make -f "$SRC/scripts/ctwo-external-modules.mk" -j"${JOBS:-$(nproc)}" \
  "KERNEL_OUT=$OUT" "LLVM=$CLANG/" \
  securemsm mmrm hw-fence sync-fence ext-display synx dsp graphics rmnet-mem rmnet-sch \
  b2-bm-adsp-ulog b2-goodix-fod b2-mmi-annotate b2-mmi-info b2-mmi-relay \
  b2-mmi-sys-temp b2-moto-usbnet b2-moto-reboot b2-moto-sched b2-sensors-class \
  b2-st54spi b2-stmvl53l3 b2-watchdogtest b2-wl2868c b2-ubwcp \
  b2-camera b2-display b2-dataipa b3-bluetooth b3-video b3-eva \
  b3-rmnet-core b3-rmnet-aps b3-rmnet-offload b3-rmnet-perf \
  b3-rmnet-perf-tether b3-rmnet-shs b3-rmnet-wlan b3-mmi-charger \
  b3-qti-charger b3-adaptive-charge b3-lpd-mitigate b3-con-dfpar \
  b3-mmap-fault b3-moto-swap b3-utags b5-audio b5-touchscreen \
  b5-goodix b5-st21nfc b5-sx937x b5-qm35 nxp-nci \
  2>&1 | tee -a "$OUT/WLAN-modules-build.log"

[[ "$(sha256sum "$IMAGE" | cut -d ' ' -f1)" == "$IMAGE_SHA256" ]] || { echo 'External build changed Image' >&2; exit 1; }
[[ "$(sha256sum "$OUT/Module.symvers" | cut -d ' ' -f1)" == "$SYMVERS_SHA256" ]] || { echo 'External build changed kernel symbols' >&2; exit 1; }
[[ "$(sha256sum "$SIGNING_KEY" | cut -d ' ' -f1)" == "$SIGNING_KEY_SHA256" ]] || { echo 'External build changed signing key' >&2; exit 1; }
[[ "$(sha256sum "$SIGNING_CERT" | cut -d ' ' -f1)" == "$SIGNING_CERT_SHA256" ]] || { echo 'External build changed signing certificate' >&2; exit 1; }
[[ "$(sha256sum "$OUT/.config" | cut -d ' ' -f1)" == "$CONFIG_SHA256" ]] || { echo 'External build changed kernel configuration' >&2; exit 1; }

WLAN_MODULES=(cnss_utils/cnss_utils.ko cnss_utils/wlan_firmware_service.ko
  cnss_utils/cnss_plat_ipc_qmi_svc.ko cnss_prealloc/cnss_prealloc.ko
  cnss_genl/cnss_nl.ko cnss2/cnss2.ko)
for ko in "$OUT/net/rfkill/rfkill.ko" "$OUT/lib/crypto/libarc4.ko" "$OUT/net/wireless/cfg80211.ko" \
  "$OUT/net/mac80211/mac80211.ko"; do
  [[ -s "$ko" ]] || { echo "Missing in-tree WLAN module: $ko" >&2; exit 1; }
done
for relative in "${WLAN_MODULES[@]}"; do
  [[ -s "$OUT/$WLAN_PLATFORM/$relative" ]] || { echo "Missing WLAN module: $relative" >&2; exit 1; }
done
WLAN_KO="$OUT/$WLAN_DRIVER/qca_cld3_kiwi_v2.ko"
[[ -s "$WLAN_KO" ]] || { echo "Missing Kiwi module: $WLAN_KO" >&2; exit 1; }

WLAN_TMP=$(mktemp -d "$OUT/.wlan-check.XXXXXXXX")
trap 'rm -rf -- "$WLAN_TMP"' EXIT
validate_module() {
  local ko=$1 name=$2 vermagic imports namespaces
  [[ "$(modinfo -F name "$ko")" == "$name" ]] || { echo "Wrong module name: $ko" >&2; return 1; }
  vermagic=$(modinfo -F vermagic "$ko")
  [[ "$vermagic" == "$RELEASE "* && "$vermagic" == *' modversions '* && "$vermagic" == *' aarch64' ]] || {
    echo "Wrong vermagic: $ko: $vermagic" >&2; return 1;
  }
  imports="$WLAN_TMP/$name.imports"
  modprobe --dump-modversions "$ko" > "$imports"
  namespaces=$(modinfo -F import_ns "$ko" | tr '\n' ',')
  awk -F '\t' -v imports="$imports" -v namespaces="$namespaces" '
    BEGIN { split(namespaces, list, ","); for (i in list) allowed[list[i]] = 1 }
    FILENAME != imports {
      if ($2 in crc && (crc[$2] != $1 || owner[$2] != $3)) {
        print "Conflicting provider for " $2 > "/dev/stderr"; bad = 1
      }
      crc[$2] = $1; owner[$2] = $3; ns[$2] = $5
      next
    }
    {
      count++
      if (!($2 in crc)) { print "Missing symbol: " $2 > "/dev/stderr"; bad = 1 }
      else if (tolower($1) != tolower(crc[$2])) {
        print "CRC mismatch: " $2 " from " owner[$2] > "/dev/stderr"; bad = 1
      } else if (ns[$2] != "" && !(ns[$2] in allowed)) {
        print "Missing namespace " ns[$2] " for " $2 > "/dev/stderr"; bad = 1
      }
    }
    END { if (!count) { print "No symbol versions found" > "/dev/stderr"; bad = 1 }; exit bad }
  ' "$OUT/Module.symvers" "$WLAN_SYMVERS" "$imports"
}
validate_module "$OUT/net/rfkill/rfkill.ko" rfkill
validate_module "$OUT/lib/crypto/libarc4.ko" libarc4
validate_module "$OUT/net/wireless/cfg80211.ko" cfg80211
validate_module "$OUT/net/mac80211/mac80211.ko" mac80211
for relative in "${WLAN_MODULES[@]}"; do
  name=${relative##*/}
  validate_module "$OUT/$WLAN_PLATFORM/$relative" "${name%.ko}"
done
validate_module "$WLAN_KO" qca_cld3_kiwi_v2

# Check dependencies against native outputs.
declare -A AVAILABLE=()
while IFS= read -r relative; do
  name=${relative##*/}
  name=${name%.ko}
  AVAILABLE[${name//-/_}]="$OUT/$relative"
done < "$OUT/modules.order"
for relative in "${WLAN_MODULES[@]}"; do
  name=${relative##*/}
  AVAILABLE[${name%.ko}]="$OUT/$WLAN_PLATFORM/$relative"
done
AVAILABLE[qca_cld3_kiwi_v2]="$WLAN_KO"
validate_dependencies() {
  local ko=$1 dependency
  local -a dependencies
  IFS=, read -r -a dependencies <<< "$(modinfo -F depends "$ko")"
  for dependency in "${dependencies[@]}"; do
    [[ -z "$dependency" ]] && continue
    [[ -s "${AVAILABLE[${dependency//-/_}]:-}" ]] || {
      echo "Missing native dependency $dependency for $ko" >&2; return 1;
    }
  done
}
validate_dependencies "$OUT/net/rfkill/rfkill.ko"
validate_dependencies "$OUT/lib/crypto/libarc4.ko"
validate_dependencies "$OUT/net/wireless/cfg80211.ko"
validate_dependencies "$OUT/net/mac80211/mac80211.ko"
for relative in "${WLAN_MODULES[@]}"; do
  validate_dependencies "$OUT/$WLAN_PLATFORM/$relative"
done
validate_dependencies "$WLAN_KO"

# Sign staging copies only.
[[ -x "$OUT/scripts/sign-file" ]] || { echo 'Missing native sign-file tool' >&2; exit 1; }
KEY_PUBLIC=$(openssl pkey -in "$SIGNING_KEY" -pubout -outform DER | sha256sum | cut -d ' ' -f1)
CERT_PUBLIC=$(openssl x509 -inform DER -in "$SIGNING_CERT" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum | cut -d ' ' -f1)
[[ "$KEY_PUBLIC" == "$CERT_PUBLIC" ]] || { echo 'Signing key and certificate do not match' >&2; exit 1; }
python3 - "$IMAGE" "$SIGNING_CERT" <<'PY'
from pathlib import Path
import sys

if Path(sys.argv[2]).read_bytes() not in Path(sys.argv[1]).read_bytes():
    sys.exit('Signing certificate is absent from the built Image')
PY
STAGE_TMP="$WLAN_TMP/stage"
verify_module_signature() {
  python3 - "$1" "$SIGNING_CERT" "$WLAN_TMP/$2.signer.pem" <<'PY'
from pathlib import Path
import subprocess, sys, tempfile

module = Path(sys.argv[1]).read_bytes()
magic = b"~Module signature appended~\n"
if not module.endswith(magic) or len(module) < len(magic) + 12:
    sys.exit(f"Missing module signature trailer: {sys.argv[1]}")
header_end = len(module) - len(magic)
signature_size = int.from_bytes(module[header_end - 4:header_end], "big")
signature_start = header_end - 12 - signature_size
if signature_size <= 0 or signature_start < 0:
    sys.exit(f"Invalid module signature trailer: {sys.argv[1]}")
with tempfile.NamedTemporaryFile() as signature:
    Path(signature.name).write_bytes(module[signature_start:signature_start + signature_size])
    result = subprocess.run([
        "openssl", "cms", "-verify", "-binary", "-inform", "DER",
        "-in", signature.name, "-content", "/dev/stdin", "-certfile", sys.argv[2],
        "-noverify", "-signer", sys.argv[3], "-out", "/dev/null",
    ], input=module[:signature_start], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
if result.returncode:
    sys.exit(f"Module signature verification failed: {result.stderr.decode(errors='replace')}")
signer = subprocess.check_output(["openssl", "x509", "-in", sys.argv[3], "-outform", "DER"])
expected = subprocess.check_output(["openssl", "x509", "-inform", "DER", "-in", sys.argv[2], "-outform", "DER"])
if signer != expected:
    sys.exit("Module signature does not use the configured kernel certificate")
PY
}
stage_module() {
  local source=$1 destination=$2 name
  mkdir -p "$(dirname "$destination")"
  cp -p -- "$source" "$destination"
  "$LLVM_STRIP" --strip-debug "$destination"
  "$OUT/scripts/sign-file" sha1 "$SIGNING_KEY" "$SIGNING_CERT" "$destination" "$destination.signed"
  mv -- "$destination.signed" "$destination"
  [[ -s "$destination" && -n "$(modinfo -F signer "$destination")" && \
    "$(modinfo -F sig_hashalgo "$destination")" == sha1 ]] || {
    echo "Invalid staged module signature: $destination" >&2; return 1;
  }
  local elf_header sections
  elf_header=$("$LLVM_READELF" -h "$destination")
  grep -Eq 'Class:[[:space:]]+ELF64' <<< "$elf_header" && \
    grep -Eq 'Type:[[:space:]]+REL \(Relocatable file\)' <<< "$elf_header" && \
    grep -Eq 'Machine:[[:space:]]+AArch64' <<< "$elf_header" || {
    echo "Invalid staged ELF module: $destination" >&2; return 1;
  }
  sections=$("$LLVM_READELF" -S "$destination")
  [[ "$sections" != *'.debug_'* ]] || { echo "Debug sections remain in $destination" >&2; return 1; }
  [[ "$(modinfo -F vermagic "$destination")" == "$(modinfo -F vermagic "$source")" ]] || {
    echo "Staging changed vermagic: $destination" >&2; return 1;
  }
  name=$(modinfo -F name "$source")
  modprobe --dump-modversions "$destination" > "$WLAN_TMP/signed.imports"
  cmp -s "$WLAN_TMP/$name.imports" "$WLAN_TMP/signed.imports" || {
    echo "Staging changed symbol versions: $destination" >&2; return 1;
  }
  modprobe --show-exports "$source" > "$WLAN_TMP/$name.exports"
  modprobe --show-exports "$destination" > "$WLAN_TMP/signed.exports"
  cmp -s "$WLAN_TMP/$name.exports" "$WLAN_TMP/signed.exports" || {
    echo "Staging changed exported symbols: $destination" >&2; return 1;
  }
  for field in name depends license alias firmware srcversion import_ns; do
    [[ "$(modinfo -F "$field" "$destination")" == "$(modinfo -F "$field" "$source")" ]] || {
      echo "Staging changed modinfo field $field: $destination" >&2; return 1;
    }
  done
  verify_module_signature "$destination" "$name"
}
stage_module "$OUT/net/rfkill/rfkill.ko" \
  "$STAGE_TMP/system_dlkm/lib/modules/$RELEASE/kernel/net/rfkill/rfkill.ko"
stage_module "$OUT/lib/crypto/libarc4.ko" \
  "$STAGE_TMP/system_dlkm/lib/modules/$RELEASE/kernel/lib/crypto/libarc4.ko"
stage_module "$OUT/net/wireless/cfg80211.ko" \
  "$STAGE_TMP/vendor_dlkm/lib/modules/cfg80211.ko"
stage_module "$OUT/net/mac80211/mac80211.ko" \
  "$STAGE_TMP/vendor_dlkm/lib/modules/mac80211.ko"
for relative in "${WLAN_MODULES[@]}"; do
  stage_module "$OUT/$WLAN_PLATFORM/$relative" \
    "$STAGE_TMP/vendor_dlkm/lib/modules/${relative##*/}"
done
stage_module "$WLAN_KO" "$STAGE_TMP/vendor_dlkm/lib/modules/qca_cld3_kiwi_v2.ko"

# Stage the extracted stock DLKM trees.
DLKM_SOURCE="$STOCK/checking/modules"
SYSTEM_DLKM_SOURCE="$DLKM_SOURCE/system_dlkm"
VENDOR_DLKM_SOURCE="$DLKM_SOURCE/vendor_dlkm"
[[ -d "$SYSTEM_DLKM_SOURCE/lib/modules" && -d "$VENDOR_DLKM_SOURCE/lib/modules" ]] || {
  echo "Missing extracted stock DLKM trees under $DLKM_SOURCE" >&2; exit 1;
}
SYSTEM_RELEASE_DIRS=("$SYSTEM_DLKM_SOURCE"/lib/modules/*)
[[ ${#SYSTEM_RELEASE_DIRS[@]} -eq 1 && -d "${SYSTEM_RELEASE_DIRS[0]}" ]] || {
  echo 'Expected exactly one extracted stock system_dlkm release directory' >&2; exit 1;
}
STOCK_SYSTEM_RELEASE=${SYSTEM_RELEASE_DIRS[0]##*/}
DLKM_TMP="$WLAN_TMP/dlkm"
mkdir -p "$DLKM_TMP/system_dlkm" "$DLKM_TMP/vendor_dlkm"
cp -a "$SYSTEM_DLKM_SOURCE/." "$DLKM_TMP/system_dlkm/"
cp -a "$VENDOR_DLKM_SOURCE/." "$DLKM_TMP/vendor_dlkm/"
mv "$DLKM_TMP/system_dlkm/lib/modules/$STOCK_SYSTEM_RELEASE" \
  "$DLKM_TMP/system_dlkm/lib/modules/$RELEASE"
install -m 0644 "$OUT/modules.builtin" \
  "$DLKM_TMP/system_dlkm/lib/modules/$RELEASE/modules.builtin"
install -m 0644 "$OUT/modules.builtin.modinfo" \
  "$DLKM_TMP/system_dlkm/lib/modules/$RELEASE/modules.builtin.modinfo"
install -m 0644 "$STAGE_TMP/system_dlkm/lib/modules/$RELEASE/kernel/net/rfkill/rfkill.ko" \
  "$DLKM_TMP/system_dlkm/lib/modules/$RELEASE/kernel/net/rfkill/rfkill.ko"
install -m 0644 "$STAGE_TMP/system_dlkm/lib/modules/$RELEASE/kernel/lib/crypto/libarc4.ko" \
  "$DLKM_TMP/system_dlkm/lib/modules/$RELEASE/kernel/lib/crypto/libarc4.ko"
for name in cfg80211 mac80211 qca_cld3_kiwi_v2; do
  install -m 0644 "$STAGE_TMP/vendor_dlkm/lib/modules/$name.ko" \
    "$DLKM_TMP/vendor_dlkm/lib/modules/$name.ko"
done
for relative in "${WLAN_MODULES[@]}"; do
  name=${relative##*/}
  install -m 0644 "$STAGE_TMP/vendor_dlkm/lib/modules/$name" \
    "$DLKM_TMP/vendor_dlkm/lib/modules/$name"
done

# Regenerate system_dlkm metadata.
"$DEPMOD" -b "$DLKM_TMP/system_dlkm" "$RELEASE" \
  2>&1 | tee "$OUT/system-dlkm-depmod.log"

# Stock vendor_dlkm is flat. Generate metadata from an isolated versioned
# view, then map module paths to the exact absolute prefix used by stock.
VENDOR_SCAN="$WLAN_TMP/vendor-depmod"
VENDOR_SCAN_MODULES="$VENDOR_SCAN/lib/modules/$RELEASE"
mkdir -p "$VENDOR_SCAN_MODULES"
find "$DLKM_TMP/vendor_dlkm/lib/modules" -maxdepth 1 -type f -name '*.ko' \
  -exec cp -p -- {} "$VENDOR_SCAN_MODULES/" \;
cp "$DLKM_TMP/vendor_dlkm/lib/modules/modules.load" "$VENDOR_SCAN_MODULES/modules.order"
: > "$VENDOR_SCAN_MODULES/modules.builtin"
: > "$VENDOR_SCAN_MODULES/modules.builtin.modinfo"
"$DEPMOD" -b "$VENDOR_SCAN" "$RELEASE" 2>&1 | tee "$OUT/vendor-dlkm-depmod.log"
python3 - "$VENDOR_SCAN_MODULES/modules.dep" "$DLKM_TMP/vendor_dlkm/lib/modules" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1])
module_dir = Path(sys.argv[2])
target = module_dir / "modules.dep"
lines = []
for line in source.read_text().splitlines():
    left, sep, right = line.partition(":")
    if not sep:
        raise SystemExit(f"Malformed depmod row: {line}")
    fields = [left.strip(), *right.split()]
    mapped = []
    for field in fields:
        name = Path(field).name
        if not name.endswith(".ko") or not (module_dir / name).is_file():
            raise SystemExit(f"depmod path has no flat vendor_dlkm module: {field}")
        mapped.append("/vendor/lib/modules/" + name)
    lines.append(mapped[0] + ":" + (" " + " ".join(mapped[1:]) if len(mapped) > 1 else ""))
target.write_text("\n".join(lines) + "\n")
PY
for metadata in modules.alias modules.softdep; do
  [[ -f "$VENDOR_SCAN_MODULES/$metadata" ]] && \
    install -m 0644 "$VENDOR_SCAN_MODULES/$metadata" "$DLKM_TMP/vendor_dlkm/lib/modules/$metadata"
done

# Check load lists and blocklists.
cmp -s "$VENDOR_DLKM_SOURCE/lib/modules/modules.load" "$DLKM_TMP/vendor_dlkm/lib/modules/modules.load" || {
  echo 'vendor_dlkm modules.load changed unexpectedly' >&2; exit 1;
}
while IFS= read -r -d '' file; do
  relative=${file#"$VENDOR_DLKM_SOURCE/"}
  cmp -s "$file" "$DLKM_TMP/vendor_dlkm/$relative" || {
    echo "vendor_dlkm blocklist changed unexpectedly: $relative" >&2; exit 1;
  }
done < <(find "$VENDOR_DLKM_SOURCE" -type f -name '*.blocklist' -print0)
python3 - "$DLKM_TMP/system_dlkm/lib/modules/$RELEASE" "$DLKM_TMP/vendor_dlkm/lib/modules" \
  "$STAGE_TMP" <<'PY'
from pathlib import Path
import subprocess, sys

system, vendor, staged = map(Path, sys.argv[1:])
for root, listing in ((system, "modules.load"), (vendor, "modules.load")):
    for line in (root / listing).read_text().splitlines():
        item = line.strip()
        if item and not (root / item).is_file():
            raise SystemExit(f"{root.name} {listing} entry missing: {item}")
for line in (system / "modules.dep").read_text().splitlines():
    left, sep, right = line.partition(":")
    if not sep:
        raise SystemExit(f"Malformed system modules.dep row: {line}")
    for item in [left.strip(), *right.split()]:
        if item.startswith("/") or not (system / item).is_file():
            raise SystemExit(f"system modules.dep path missing or unexpected: {item}")
for line in (vendor / "modules.dep").read_text().splitlines():
    left, sep, right = line.partition(":")
    if not sep:
        raise SystemExit(f"Malformed vendor modules.dep row: {line}")
    for item in [left.strip(), *right.split()]:
        prefix = "/vendor/lib/modules/"
        if not item.startswith(prefix) or not (vendor / item[len(prefix):]).is_file():
            raise SystemExit(f"vendor modules.dep path missing or unexpected: {item}")
for root in (system, vendor):
    aliases = (root / "modules.alias").read_text().splitlines()
    modules = list(root.rglob("*.ko"))
    for module in modules:
        name = subprocess.check_output(["modinfo", "-F", "name", str(module)], text=True).strip()
        for alias in subprocess.check_output(["modinfo", "-F", "alias", str(module)], text=True).splitlines():
            if alias and f"alias {alias} {name}" not in aliases:
                raise SystemExit(f"Alias absent from generated modules.alias: {name}: {alias}")
for name in ("cfg80211", "mac80211", "cnss2", "cnss_nl", "cnss_prealloc",
             "cnss_plat_ipc_qmi_svc", "cnss_utils", "wlan_firmware_service", "qca_cld3_kiwi_v2"):
    if not any(line.strip() == name + ".ko" for line in (vendor / "modules.load").read_text().splitlines()):
        raise SystemExit(f"Target module absent from vendor modules.load: {name}")
if not any(line.strip().endswith("rfkill.ko") for line in (system / "modules.load").read_text().splitlines()):
    raise SystemExit("rfkill absent from system_dlkm modules.load")
PY

DLKM_STAGE="$OUT/dlkm-staging/${IMAGE_SHA256:0:12}-$RELEASE-${WLAN_TMP##*.}"
[[ ! -e "$DLKM_STAGE" ]] || { echo "Refusing to overwrite DLKM staging tree: $DLKM_STAGE" >&2; exit 1; }
mkdir -p "$OUT/dlkm-staging"
mv -T -- "$DLKM_TMP" "$DLKM_STAGE"
printf '[ok] modules staged\n'

mkdir -p "$OUT/wlan-staging"
STAGE="$OUT/wlan-staging/${IMAGE_SHA256:0:12}-${WLAN_TMP##*.}"
[[ ! -e "$STAGE" ]] || { echo "Refusing to overwrite staging directory: $STAGE" >&2; exit 1; }
mv -T -- "$STAGE_TMP" "$STAGE"

STOCK_BOOT="$STOCK/boot.img"
[[ "$(sha256sum "$STOCK_BOOT" | cut -d ' ' -f1)" == "$EXPECTED_STOCK_BOOT_SHA256" ]] || { echo 'Stock boot.img does not match the validated firmware' >&2; exit 1; }
[[ "$(sha256sum "$STOCK/vbmeta.img" | cut -d ' ' -f1)" == "$EXPECTED_STOCK_VBMETA_SHA256" ]] || { echo 'Stock vbmeta.img does not match the validated firmware' >&2; exit 1; }
TMP=$(mktemp -d "$BUILD/.native-boot.XXXXXX")
trap 'rm -rf -- "$WLAN_TMP" "$TMP"' EXIT
unpack_bootimg --boot_img "$STOCK_BOOT" --out "$TMP/stock" --format=info > "$TMP/stock-info"
grep -Fxq 'boot image header version: 4' "$TMP/stock-info" || { echo 'Stock boot header is not v4' >&2; exit 1; }
grep -Fxq 'ramdisk size: 0' "$TMP/stock-info" || { echo 'Unexpected stock boot ramdisk' >&2; exit 1; }
mkbootimg --header_version 4 --kernel "$IMAGE" --ramdisk "$TMP/stock/ramdisk" \
  --cmdline '' --output "$TMP/boot.img"
avbtool add_hash_footer --image "$TMP/boot.img" --partition_size "$PARTITION_SIZE" \
  --partition_name boot --hash_algorithm sha256 \
  --salt baef919029f01159aaf488a149e4b95800e43a5733d30bbe349e2acfe70644eb \
  --prop com.android.build.boot.os_version:14 \
  --prop com.android.build.boot.fingerprint:motorola/ctwo/ctwo:14/UUV3S4HV-W1-ST14/cb805:user/release-keys \
  --prop com.android.build.boot.security_patch:2026-08-01 \
  --prop com.android.build.boot.security_patch:2026-08-01

[[ "$(stat -c '%s' "$TMP/boot.img")" == "$PARTITION_SIZE" ]] || { echo 'Packaged boot image has unexpected size' >&2; exit 1; }
unpack_bootimg --boot_img "$TMP/boot.img" --out "$TMP/check" --format=info > "$TMP/check-info"
grep -Fxq 'boot image header version: 4' "$TMP/check-info" || { echo 'Packaged header validation failed' >&2; exit 1; }
[[ "$(sha256sum "$TMP/check/kernel" | cut -d ' ' -f1)" == "$IMAGE_SHA256" ]] || { echo 'Embedded kernel hash mismatch' >&2; exit 1; }
avbtool verify_image --image "$TMP/boot.img"
AVB_INFO=$(avbtool info_image --image "$TMP/boot.img")
AVB_DIGEST=$(awk '/Digest:/ {print $2; exit}' <<< "$AVB_INFO")
[[ "$AVB_DIGEST" != "$STOCK_BOOT_DIGEST" ]] || { echo 'Unexpectedly matches the stock root vbmeta boot digest' >&2; exit 1; }

PACKAGE="$BUILD/boot-ctwo-native-${IMAGE_SHA256:0:12}.img"
if [[ -e "$PACKAGE" ]]; then
  cmp -s "$TMP/boot.img" "$PACKAGE" || { echo "Refusing to overwrite different image: $PACKAGE" >&2; exit 1; }
else
  install -m 0644 "$TMP/boot.img" "$PACKAGE"
fi
python3 "$SRC/scripts/ctwo-package-boot.py" \
  --out "$OUT" --build "$BUILD" --stock "$STOCK" \
  --boot "$PACKAGE" --image-sha256 "$IMAGE_SHA256" --dlkm-stage "$DLKM_STAGE"
python3 "$SRC/scripts/ctwo-package-dlkm.py" \
  --out "$OUT" --build "$BUILD" --stock "$STOCK" \
  --image-sha256 "$IMAGE_SHA256"
printf '[ok] kernel built (sha256 %.6s)\n' "$IMAGE_SHA256"
printf '[ok] modules packaged\n'
