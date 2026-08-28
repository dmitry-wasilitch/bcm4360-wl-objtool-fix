# Test results

- Test date: 2026-08-28
- Kernel: `7.2.0-1-cachyos`
- Driver: `broadcom-wl 6.30.223.271`

## Static gates

| Gate | Result |
|---|---:|
| Closed object SHA-256 pinned | PASS |
| Module vermagic matches running kernel | PASS |
| DKMS PKCS#7 signature present | PASS |
| `.return_sites` present | PASS |
| Return-thunk relocations covered | 156 / 156 |
| ORC/retpoline/IBT record layout | PASS |
| Raw returns in open glue | 0 |
| Raw returns confined to closed object | 3922 |
| Exact installed DKMS artifact checked | PASS |
| Stable-input snapshots and bounded tool output | PASS |
| Missing-metadata mutation rejected | PASS |
| Wrong-vermagic input rejected | PASS |
| Verifier negative tests | 23 / 23 |

Pinned closed-object SHA-256:

```text
352a6e349f74c69b78e76f68c63752c99b8f6b22dc942af531b754211d7f4743
```

The signed and compressed module hash is intentionally not a portable expected
value. DKMS signatures can differ between machines.

Both the clean unsigned build and the signed module selected by `modinfo` under
`/lib/modules/7.2.0-1-cachyos` passed the same structural gate. The latter was
decompressed into a private temporary directory for inspection; the installed
file was not modified.

## Live gates

| Check | Result |
|---|---:|
| Module load | PASS |
| PCI probe and bind | PASS |
| `wlan0` creation | PASS |
| Direct 2.4/5 GHz scan | PASS |
| 5 GHz association and traffic | PASS |
| NetworkManager supplicant acquisition | PASS |
| Cold userspace-order simulation | PASS |
| Full reboot and early module load | PASS |
| Saved-profile autoconnect | PASS |
| 5 GHz association after reboot | 5500 MHz |
| WPA2 four-way handshake | PASS |
| DHCP lease | PASS |
| Wi-Fi gateway traffic | 0% loss |
| Wi-Fi Internet traffic | 0% loss |
| Wired route retained at lower metric | PASS |
| `Unpatched return thunk` after test marker | 0 occurrences |
| Oops / call trace / protection fault | 0 occurrences |

The driver prints its upstream warning about being unmaintained. Requests for
tx-power can also print `wl_cfg80211_get_tx_power`; neither affected scan,
association or the tested data path.

The cold-order check first stopped NetworkManager and `wpa_supplicant`, unloaded
`wl`, loaded it through the installed `modules-load.d` entry, and then started
NetworkManager. A subsequent full reboot confirmed the same path:
`systemd-modules-load` inserted `wl` before NetworkManager, the saved profile
associated on 5500 MHz and obtained DHCP without manual recovery. Wired Ethernet
remained the preferred default route at metric 100; Wi-Fi used metric 600.
