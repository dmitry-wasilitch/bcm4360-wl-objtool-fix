# BCM4360 `wl` on Linux 7.2 without skipping objtool for the open glue

Broadcom's proprietary `wl` driver still supports BCM4360 hardware, but its
legacy binary object cannot pass current kernel control-flow validation. Recent
community packages often make Linux 7.x builds green by disabling objtool for
the whole module. That also drops return-site and ORC metadata for the C glue
which is compiled locally.

This repository contains the smaller fix I use on CachyOS: run the kernel's
real objtool on every open glue object, then link Broadcom's closed object only
at the final composite stage.

Tested on:

- BCM4360 `14e4:43a0`, revision 03
- Apple subsystem `106b:0111`
- CachyOS `7.2.0-1-cachyos`
- `broadcom-wl-dkms 6.30.223.271-49`

The resulting module associates through NetworkManager, completes WPA2 and
DHCP, and passes traffic over both 2.4 and 5 GHz. After a normal reboot the
saved profile reconnects on 5 GHz without manual recovery. The original
`Unpatched return thunk in use` warning is gone.

## What changes

`patches/linux-7.2-string-api.patch` replaces the removed legacy `strncpy`
calls with bounded kernel helpers. The hardening fix itself is in
`patches/linux-7.2-objtool-glue.patch`, which makes three relevant changes:

```make
LDFLAGS_wl.o := /usr/lib/broadcom-wl-dkms/wlc_hybrid.o_shipped
ccflags-y += -fno-lto
$(wl-objs): override objtool-enabled = y
```

The target-specific linker flag prevents the proprietary object from being
injected into Kbuild's per-object native-LTO relinks. Disabling ThinLTO for the
four glue translation units turns them into ordinary ELF objects. Each object
then runs through the exact kernel objtool with the normal delayed-mode
`--link --module` arguments.

The final `wl.o` exception remains because it contains the closed object. That
exception is a compatibility boundary, not a hardening claim.

## Static result

On the tested build:

```text
open-glue jumps to __x86_return_thunk: 156
.return_sites entries:                  156
decoded raw returns in open glue:         0
decoded raw returns in closed object:  3922
```

`tools/verify_wl_hardening.py` checks the pinned blob, its byte-identical
closed-code prefix in the final module, vermagic, PKCS#7 signature metadata,
ELF section and boundary-symbol semantics, instruction bytes, relocation types
and slots, return-site coverage, and the record layout of ORC, retpoline and
IBT metadata. Inputs are copied once into private snapshots before analysis;
the external tools have fixed paths, output caps and a total deadline.

Run a clean build and the gate against its own four glue objects with:

```bash
tools/build_and_verify.sh 7.2.0-1-cachyos
```

The helper authenticates the proprietary blob before invoking Kbuild, builds
in a temporary directory and removes it afterwards. It uses
`--unsigned-build-tree` because module signing happens later in DKMS; the
normal verifier mode requires PKCS#7 fields. Those fields prove that signing
metadata is present, not that a particular machine trusts the key.

This is a structural gate for a locally controlled build. The four `--glue`
paths are separate inputs, so the command is not an authenticity check for an
untrusted third-party module.

## DKMS integration

This patch was developed against the Arch/CachyOS `broadcom-wl-dkms` layout.
Do not apply it to an unknown blob or another driver version without repeating
the static audit.

```bash
sudo install -D -m 0644 patches/linux-7.2-string-api.patch \
  /etc/dkms/broadcom-wl/patches/linux-7.2-string-api.patch

sudo install -D -m 0644 patches/linux-7.2-objtool-glue.patch \
  /etc/dkms/broadcom-wl/patches/linux-7.2-objtool-glue.patch

sudo install -D -m 0644 config/broadcom-wl.conf \
  /etc/dkms/broadcom-wl.conf

sudo dkms build --force \
  -m broadcom-wl -v 6.30.223.271 -k 7.2.0-1-cachyos

sudo dkms install --force \
  -m broadcom-wl -v 6.30.223.271 -k 7.2.0-1-cachyos

tools/verify_installed_module.sh 7.2.0-1-cachyos

sudo install -D -m 0644 config/modules-load.d/broadcom-wl.conf \
  /etc/modules-load.d/broadcom-wl.conf

sudo install -D -m 0644 config/NetworkManager/30-broadcom-wl.conf \
  /etc/NetworkManager/conf.d/30-broadcom-wl.conf
```

The clean-build helper proves the source and patch path, but does not install
its temporary output. The second helper decompresses and checks the exact
module selected by `modinfo` under `/lib/modules/<kernel>` after DKMS installs
it. This distinction matters: `dkms install --force` alone may reuse a cached
build, so a changed timestamp is not evidence that the patch was compiled.
Verify the installed file before loading it or before the next boot.

The optional NetworkManager snippet is scoped to `driver:wl`. It disables scan
MAC randomization because this legacy driver does not reliably handle that
operation. Other Wi-Fi devices keep NetworkManager's default behavior.

`modules-load.d` loads the patched module in early userspace. On a normal boot,
`systemd-modules-load.service` finishes before `sysinit.target`; NetworkManager
starts later and sees a newly created interface instead of racing a hot-removed
one. `wpa_supplicant.service` can remain disabled: NetworkManager starts it over
D-Bus when Wi-Fi is needed.

The tested connection profile has autoconnect enabled. Wired Ethernet keeps the
lower route metric, so bringing up Wi-Fi does not replace the primary route.

## What this does not fix

This is not a free BCM4360 driver and it does not modernize Broadcom's closed
machine code. The proprietary object still lacks complete RETHUNK, IBT, SLS,
ORC and retpoline coverage. It cannot be safely transformed in place: its raw
one-byte returns are commonly followed immediately by the next function.

The kernel warning that describes `broadcom-wl` as unmaintained and
incompatible with some mitigations remains correct. Replacing the Wi-Fi card is
still the clean long-term solution.

## Repository policy

No Broadcom binary, firmware, built kernel module, signing key, Wi-Fi profile or
machine log is included here. The patches require a separately obtained
`broadcom-wl` package.

The complete investigation is in [docs/technical-notes.md](docs/technical-notes.md).

## Author

**Dmitry Wasilitch**

Reproducible results from other kernels and BCM4360 revisions are welcome,
including failed tests.
