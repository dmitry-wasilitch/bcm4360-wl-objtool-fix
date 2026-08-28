#!/usr/bin/env bash
set -euo pipefail

export PATH=/usr/sbin:/usr/bin:/sbin:/bin

readonly expected_blob_sha256=352a6e349f74c69b78e76f68c63752c99b8f6b22dc942af531b754211d7f4743
kernel=${1:-$(/usr/bin/uname -r)}
if [[ ! $kernel =~ ^[A-Za-z0-9._+-]+$ || $kernel == . || $kernel == .. ]]; then
    printf 'invalid kernel release: %s\n' "$kernel" >&2
    exit 2
fi

repo=$(/usr/bin/realpath -e -- "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")/..")
source_tree=/usr/src/broadcom-wl-6.30.223.271
modules_root=$(/usr/bin/realpath -e -- /lib/modules)
kernel_tree_candidate=/lib/modules/${kernel}/build
blob=/usr/lib/broadcom-wl-dkms/wlc_hybrid.o_shipped
build_tree=$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/bcm4360-wl-build.XXXXXX")

cleanup() {
    /usr/bin/rm -rf -- "$build_tree"
}
trap cleanup EXIT

for path in "$source_tree" "$kernel_tree_candidate" "$blob"; do
    if [[ ! -e $path ]]; then
        printf 'missing required path: %s\n' "$path" >&2
        exit 1
    fi
done

kernel_tree=$(/usr/bin/realpath -e -- "$kernel_tree_candidate")
case "$kernel_tree/" in
    "$modules_root/"*) ;;
    *)
        printf 'kernel build tree escapes %s: %s\n' "$modules_root" "$kernel_tree" >&2
        exit 1
        ;;
esac

actual_blob_sha256=$(/usr/bin/sha256sum -- "$blob")
actual_blob_sha256=${actual_blob_sha256%% *}
if [[ $actual_blob_sha256 != "$expected_blob_sha256" ]]; then
    printf 'closed blob hash mismatch: %s\n' "$actual_blob_sha256" >&2
    exit 1
fi

/usr/bin/cp -a -- "$source_tree/." "$build_tree/"
/usr/bin/patch --batch --forward -d "$build_tree" -p1 \
    < "$repo/patches/linux-7.2-string-api.patch"
/usr/bin/patch --batch --forward -d "$build_tree" -p1 \
    < "$repo/patches/linux-7.2-objtool-glue.patch"

/usr/bin/make -C "$kernel_tree" M="$build_tree" LLVM=1 clean
/usr/bin/make -C "$kernel_tree" M="$build_tree" LLVM=1

PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 "$repo/tools/test_verify_wl_hardening.py" -v

PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 "$repo/tools/verify_wl_hardening.py" \
    "$build_tree/wl.ko" "$blob" --kernel "$kernel" \
    --unsigned-build-tree \
    --glue "$build_tree/src/shared/linux_osl.o" \
    --glue "$build_tree/src/wl/sys/wl_linux.o" \
    --glue "$build_tree/src/wl/sys/wl_iw.o" \
    --glue "$build_tree/src/wl/sys/wl_cfg80211_hybrid.o"
