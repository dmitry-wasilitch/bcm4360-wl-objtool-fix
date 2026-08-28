#!/usr/bin/env bash
set -euo pipefail

export PATH=/usr/sbin:/usr/bin:/sbin:/bin

kernel=${1:-$(/usr/bin/uname -r)}
if [[ ! $kernel =~ ^[A-Za-z0-9._+-]+$ || $kernel == . || $kernel == .. ]]; then
    printf 'invalid kernel release: %s\n' "$kernel" >&2
    exit 2
fi

repo=$(/usr/bin/realpath -e -- "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")/..")
blob=/usr/lib/broadcom-wl-dkms/wlc_hybrid.o_shipped
kernel_module_root=$(/usr/bin/realpath -e -- "/lib/modules/$kernel")
installed=$(/usr/bin/modinfo -k "$kernel" -n wl)
installed=$(/usr/bin/realpath -e -- "$installed")
case "$installed" in
    "$kernel_module_root"/*) ;;
    *)
        printf 'module path escapes %s: %s\n' "$kernel_module_root" "$installed" >&2
        exit 1
        ;;
esac
work_tree=$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/bcm4360-wl-installed.XXXXXX")

cleanup() {
    /usr/bin/rm -rf -- "$work_tree"
}
trap cleanup EXIT

module="$work_tree/wl.ko"
case "$installed" in
    *.zst)
        /usr/bin/zstd --quiet --decompress --force -o "$module" -- "$installed"
        ;;
    *.ko)
        /usr/bin/cp -- "$installed" "$module"
        ;;
    *)
        printf 'unsupported installed module format: %s\n' "$installed" >&2
        exit 1
        ;;
esac

PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 "$repo/tools/verify_wl_hardening.py" \
    "$module" "$blob" --kernel "$kernel"
