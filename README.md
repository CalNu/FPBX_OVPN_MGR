# OpenVPN Manager (`ovpn_mgr`) for FreePBX

**Version:** 3.05 | **License:** GPLv3+ | **Category:** Utilities

A FreePBX module that runs and manages OpenVPN servers for remote SIP phones, and builds the per-phone provisioning packages that connect them. It is designed to work alongside the Yealink Endpoint Manager module (`yealink_epm`), which can use it to generate and revoke VPN keys for a phone.

---

## What it does

- **Runs two OpenVPN servers side by side**, each with its own PKI, UDP port, VPN subnet, logs and systemd unit:
  - **Modern** (AES-GCM): RSA-2048 / SHA-256 certificates, TLS 1.2 or newer, no DH parameters. Use this for every phone and app that supports it.
  - **Legacy** (AES-CBC): RSA-1024 / SHA-1 certificates, 1024-bit DH, TLS 1.0 or newer. It exists only for old phone firmware (for example the Yealink T28P) that cannot verify SHA-256 signatures. **See the security warning below.**
- **Builds provisioning packages** per extension/MAC: a certificate, key and `vpn.cnf` bundled as a `.tar`, or a single-file `.ovpn` with the CA, certificate and key inline. The tab open in OpenVPN Server Settings decides the cipher list: Modern offers only the AES-GCM ciphers and Legacy only the AES-CBC ciphers. The Legacy tab shows a red warning, and Legacy packages cannot be built until you press its acknowledgment button once (it is remembered).
- **Manages keys:** revoke, delete, rebuild, change cipher, and move a phone between servers. Revoking a key also ends that phone's live session.
- **Shows live state:** connected clients (real IP, virtual IP, active cipher, with a link to the phone's web UI), live logs for both servers, start/stop/restart controls, and a "Restart needed" notice when a running daemon is out of step with its config.
- **Warns about shared packages:** a banner appears when one package is being used by more than one device.
- **Handles routing and access for you:**
  - Per-client route to the PBX LAN address, so phones on the PBX LAN and remote phones can share a server.
  - A "VPN Access" list of networks allowed to reach the phones' VPN addresses (masqueraded into both tunnels).
  - NAT, IP forwarding and the UDP port rules, restored at boot.
- **Integrates with FreePBX:** adds the VPN subnets to FreePBX Firewall (Trusted zone), Fail2Ban `ignoreip` and Asterisk SIP "Local Networks", and labels the tunnel interfaces.

---

## Security warning: the Legacy server and its cipher/crypto settings

> **The Legacy server uses cryptography that is considered obsolete. Run it only if you have phones that cannot work with the Modern server, and treat everything that connects to it as less trusted than everything else on your network.**

### What "legacy" means here

| Setting | Legacy server | Modern server |
|---|---|---|
| Certificate key | RSA-1024 | RSA-2048 |
| Certificate signature | SHA-1 | SHA-256 |
| Diffie-Hellman | 1024-bit | none |
| Minimum TLS | 1.0 | 1.2 |
| Data channel | AES-CBC (256 by default, AES-128 also offered) with HMAC-SHA1 (`auth SHA1`) | AES-GCM only |
| Client-side cert checks | Relaxed (`tls-cert-profile insecure`, lowered OpenSSL security level, legacy provider) | Normal |

### Why it matters

- **RSA-1024 is no longer considered safe.** It has been deprecated by standards bodies for over a decade. Factoring a 1024-bit key is expensive, but it is within reach of a well-resourced attacker. If the legacy CA or server private key is ever recovered, an attacker can impersonate your VPN server or mint certificates that your server will accept.
- **SHA-1 signatures can be forged in practice.** Practical SHA-1 collision attacks have been demonstrated, including chosen-prefix collisions. This weakens the guarantee that a certificate really was issued by your CA.
- **1024-bit Diffie-Hellman and TLS 1.0 are weak key exchange and protocol choices.** They are the type of settings that downgrade and pre-computation attacks target. Because the server accepts TLS 1.0 and a lowered security level, it will also accept weaker handshakes than a modern server would.
- **CBC with HMAC-SHA1 is not an AEAD mode.** AES-CBC is not itself broken, and OpenVPN's data channel authenticates traffic, so the AES cipher is not the weakest link. The weak links are the certificates, the key exchange and the protocol versions around it, and that is what the Legacy label really covers. Do not treat "AES-256" as meaning the tunnel is strong.
- **No `tls-auth` / `tls-crypt` is configured by the module.** The legacy UDP port will answer anyone who can reach it, so the weak TLS stack is exposed to the internet if you forward that port.
- **Long-lived certificates.** The legacy CA and server certificates are issued for 10 years. A weak key that lives that long is a long-term exposure.
- **The module trusts the VPN subnets.** By design it adds each VPN subnet to the FreePBX Firewall **Trusted** zone, to Fail2Ban `ignoreip`, and to SIP Local Networks. A compromised or impersonated legacy client therefore lands in a trusted position next to your PBX, and brute-force attempts from the legacy pool are not banned.
- **Packages hold a private key.** Downloaded `.ovpn` files and provisioning `.tar` files contain the client key. For legacy profiles, the module adds `tls-cert-profile insecure` so current clients accept the weak certificates, which also means those clients will accept other weak certificates.

### Reducing the risk

1. **Use the Modern server for everything that supports it** (for example OpenVPN Connect and newer Yealink models). Build packages with the Modern tab open in Server Settings, which offers only `AES-256-GCM` and `AES-128-GCM`. The Legacy tab carries a red warning and a one-time acknowledgment button that must be pressed before a Legacy package can be built, and the module checks that on the server side too.
2. **Keep the Legacy server for the phones that need it** and migrate them as soon as the firmware allows. The Edit and "Move" actions in Manage / Revoke Keys help with that.
3. **Restrict who can reach the legacy UDP port.** If your phones have fixed public addresses or sites, allow only those sources in your firewall rather than exposing the port to the whole internet.
4. **Do not leave the legacy subnet in the Trusted zone any wider than needed.** Review the Trusted zone and the "VPN Access" list, and consider limiting what the legacy subnet can reach.
5. **One package per device, and revoke promptly.** Revoke packages for retired or lost phones, and act on the shared-package warning.
6. **Protect the PKI directory.** The legacy CA key lives under `PhoneSettings/openvpn/legacy_pki/private`. Keep backups of it private and restrict access to the PBX.
7. **Watch the logs.** Use View Live Logs for repeated failed handshakes or unexpected client addresses.
8. **Keep OpenVPN and OpenSSL updated,** and do not enable weaker options than the module already sets.


If a device can only work with the Legacy server, assume that VPN offers *obfuscation and basic authentication*, not strong protection against a determined attacker, and do not carry sensitive traffic over it that you would not be comfortable exposing.

---

## Requirements

- FreePBX (FreePBX 16 and 17 / Debian and CentOS-based systems are handled by the installer) with `systemd` and `sudo`.
- OpenVPN and OpenSSL installed on the PBX. On OpenSSL 3 the legacy server uses the legacy provider.
- Root shell access, once, to run the setup script.

## Installation

1. Upload the module in **Admin > Module Admin** (or place it in `admin/modules/ovpn_mgr`) and install it. This creates both PKIs and server configs without disturbing an existing legacy setup.
2. Run the one-time root setup from an SSH/console root shell:

   ```bash
   sudo bash /path/to/admin/modules/ovpn_mgr/scripts/setup-root.sh
   ```

   This locks down `scripts/ovpnctl` (`root:asterisk`, `0750`), installs a `sudoers` rule that lets the `asterisk` user run only the module's two helper scripts, persists IP forwarding, installs the systemd units (OpenVPN, NAT restore, permission watcher), registers the ports/subnets with FreePBX Firewall, and updates Fail2Ban and SIP Local Networks. Re-running it does not restart a healthy daemon; add `--restart-vpn` when an upgrade changelog says a restart is needed.
3. Open **Utilities > OpenVPN Manager**, start the server(s), then build provisioning packages.

After each module upgrade, re-run `setup-root.sh` if the page shows the setup banner or the changelog tells you to.

## Using it

1. **Server Settings:** choose the Modern or Legacy tab. Set the server host (IP or FQDN), port and VPN subnet. *Save Settings* never restarts the daemon; *Save & Restart Daemon* applies a pending port/subnet change.
2. **Build Provisioning Package:** the cipher list follows the tab open in Server Settings: **Modern** shows `AES-256-GCM` / `AES-128-GCM`, **Legacy** shows `AES-256-CBC` / `AES-128-CBC`. On the Legacy tab, press the acknowledgment button under the red warning first (one time only; it is remembered in `PhoneSettings/openvpn/.legacy_ack`, and deleting that file asks again); until then the build form is locked. Then pick an extension and MAC (or any label) and a cipher. The Edit and Change Cipher dialogs are blocked from choosing a CBC cipher until it has been given.
3. **Deliver the package** to the phone (via provisioning or the `.ovpn` download).
4. **Monitor:** check Connected OpenVPN Clients, the live log, and the warning banners.
5. **Revoke / rebuild** from Manage / Revoke Keys when a phone changes address, firmware or is retired.

Some Yealink phones hang on "obtaining IP address" when `vpn.cnf` uses a hostname instead of an IP; use an IP address or give the phone a static IP.

## Files

| Path | Purpose |
|---|---|
| `page.ovpn_mgr.php` | Admin page and UI |
| `Ovpn_mgr.class.php` | FreePBX BMO class (ajax log viewer, module hooks) |
| `lib/client_ops.php` | PKI, package building, config and daemon logic |
| `install.php` / `uninstall.php` | Install, upgrade and cleanup (uninstall never deletes keys or packages) |
| `scripts/setup-root.sh` | One-time privileged setup |
| `scripts/ovpnctl` | Root helper called through `sudo` by the GUI |
| `scripts/fw-register.php`, `fail2ban-whitelist.php`, `sip-localnet-sync.php`, `kill-client.php` | Firewall, Fail2Ban, SIP and session helpers |
| `devtools/` | Developer scripts (reset, signing); not for production use |
| `changelog.txt` | Full version history |

## Links

- Source: https://github.com/CalNu/FPBX_OVPN_MGR
- Changelog: see `changelog.txt`
