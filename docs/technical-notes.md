# Technical notes

## Module layout

The Arch/CachyOS package links four open objects with Broadcom's shipped ELF:

```text
src/shared/linux_osl.o
src/wl/sys/wl_linux.o
src/wl/sys/wl_iw.o
src/wl/sys/wl_cfg80211_hybrid.o
wlc_hybrid.o_shipped
```

The shipped object's `.text` is `0x181130` bytes. In the final module it is a
bit-identical prefix; the locally compiled glue starts immediately afterward.
The object reports GCC 4.4.7 provenance and contains 2722 function symbols.

This is a host-side D11/BMAC/PHY stack, not a BCDC-over-PCIe FullMAC transport
that can be dropped into `brcmfmac`. Its embedded ARM image is an optional
offload component. Linux PCI setup lives in the open glue, while D11 control,
DMA, MAC/PHY and most 802.11 logic live in the closed object.

## Why the installed module warned

CachyOS compiles the glue with `-mfunction-return=thunk-extern`. Function
returns therefore become jumps to `__x86_return_thunk`. During module
finalization the kernel rewrites those jumps only when `.return_sites` exists.

The package disables objtool on final `wl.o` because that is the first stage
where the closed object is present. ThinLTO delays objtool until the same final
stage, so the open glue never gets processed either. The module retained its
compiler-generated thunk jumps but had no `.return_sites`; execution reached
the kernel warning stub.

`modinfo retpoline: Y` is not proof of coverage. Kbuild stamps that module-info
field independently of whether objtool processed the driver.

## Why whole-module objtool cannot work

The exact kernel objtool first stops at:

```text
aes_cbc_encrypt_pad+0x4c: unannotated intra-function call
```

The proprietary object contains direct calls without relocations and without
function symbols at their destinations. Reconstructing local symbols gets past
the first error but exposes further control-flow and mitigation violations.

Most importantly, objtool does not translate raw `ret` instructions into
return-thunk jumps. The compiler must emit the thunk form. The closed object
contains 3922 decoded one-byte returns and no general padding scheme suitable
for a five-byte jump. In 1846 locations, `c3` is followed by bytes matching the
common `push %rbp; mov %rsp,%rbp` prologue. That byte pattern alone is not proof
of a function boundary, but it demonstrates why in-place widening is unsafe.

Fabricating `.return_sites` entries for opcode `c3` would not help. The kernel's
`apply_returns()` accepts a JMP32 whose destination is
`__x86_return_thunk`, not a raw return.

## Per-object boundary

Linux 7.2 also needs a small, separate source-compatibility patch for the
removed `strncpy` API. It uses `strscpy_pad` where the old wrapper promised
padding and `strscpy` for fixed-size version and interface-name buffers. This
change only gets the old glue compiling; it does not address objtool metadata.

The working build changes the scope of the existing exception:

1. `LDFLAGS_wl.o` adds the proprietary object only to final `wl.o`.
2. `-fno-lto` produces native ELF for the four open objects.
3. `$(wl-objs): override objtool-enabled = y` overrides ThinLTO's delayed skip.
4. Each open object runs through the CachyOS 7.2 objtool with
   `--ibt --orc --retpoline --rethunk --sls --link --module` and the remaining
   kernel-selected flags.
5. Final composite objtool remains disabled because the closed object cannot be
   validated.

This creates return-site, ORC, retpoline and IBT-seal metadata for code that can
actually be rebuilt without pretending that the proprietary region is clean.

The verifier does not infer this from section names alone. It checks contiguous
PC-relative relocation records for `.return_sites`, `.retpoline_sites`,
`.ibt_endbr_seal` and `.orc_unwind_ip`, and requires the six-byte ORC record
array to match the IP-record count. It independently decodes return opcodes
(including legacy-prefixed and far-return forms), snapshots every input once,
and compares the exact return locations in the final module with the pinned
closed object. These are structural checks; they are not a proof that the
proprietary instructions implement safe semantics.

`build_and_verify.sh` checks a clean unsigned build together with all four glue
objects. `verify_installed_module.sh` separately checks the signed module that
DKMS actually placed under `/lib/modules`. A loaded copy predating that check
must still be reloaded or left for the next normal boot.

## Community status

- Current Linux `b43` still marks AC PHY support for BCM4352/BCM4360 as broken.
- `kimptoc/bcm4360-re` documents useful firmware work but is on hold and is not
  a scanning/associating/TX/RX driver.
- Recent Linux 7.x `broadcom-wl` forks provide useful API patches. Several make
  the build pass with `objtool=/bin/true`, which is unsuitable as a hardening
  result.

Relevant upstream material:

- <https://github.com/torvalds/linux/blob/master/drivers/net/wireless/broadcom/b43/Kconfig>
- <https://github.com/kimptoc/bcm4360-re>
- <https://github.com/jpsolares/broadcom-wl-dkms>
- <https://sources.debian.org/patches/broadcom-sta/6.30.223.271-32/>
