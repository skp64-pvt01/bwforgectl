---
---
## Known Issues / Todo

### 🔴 Misassigned SSH Keys
| Key File | Authenticates As | Should Be |
|:---------|:----------------|:----------|
| `id_ed25519-newbyc333@gmail.com` | skp1964-dev (GitHub) | newbyc333 |
| `id_rsa_proteus.cpi.3` | skp64-pvtconfs (GitHub), skp64prj-shared01 (GitLab) | proteus / proteus.cpi.3 |
| `id_ed25519-goofybits@gmail.com` | skp64prj-shared01 (GitLab) | goofybits |
| `id_ed25519-pilakkat@gmail.com` | skp64prj-shared01 (GitLab) | pilakkat |
**Fix**: Generate and register new unique SSH keys for these accounts.

### 🔴 Missing SSH Keys
- **skp64prj-hub01** (GitHub) — has creds + TOTP in BW, no SSH key
- **skp64-dev** (GitLab) — has creds in BW, no SSH key
**Fix**: Generate keys and register on respective platforms.

### 🟡 Self-hosted GitLab Instances
6 instances (freeddns, ddns.net, pilakkat.net, gitlabee, 5GES ASTAR) have creds in BW but no SSH keys. Most unreachable from current environment.

### 🟡 Duplicate BW Items
Some accounts have multiple BW records (e.g., `skp64prj-hub01` appears 4×: main, email variant, TOTP-only, and `GitHub` entry). Consolidate.

### 🟡 Mystery Account: `git: github: pilakkat`
BW has a type-1 login with username `pilakkat@gmail.com` and a password. May be a non-SSH web-login-only account — verify if this is a real GitHub account.

---

## Naming Convention

### SSH Key Files
```
id_ed25519-<registered-email>
```
No angle brackets in filenames. Clean email-as-filename format.
For same-base gmail with multiple accounts: `id_ed25519-<base>+<suffix>@gmail.com`

### Bitwarden Records
- **Login credentials**: `git: <platform>: <account-name>`
- **SSH Key items**: `id_ed25519-<email>` (matches key filename for bwforgectl sync)
- **Tokens**: `git: <platform>: <account-name>: <type>`
- **Self-hosted**: `git: <hostname>: <username>`

### SSH Config Hosts
- GitHub: `git.<account-name>.com`
- GitLab: `gitlab.<account-name>.com`

---

## Github Accounts

| No  | User Name     | Primary Email                       | SSH Key Filename                         | BW Record Name                   | SSH Verified                  | Password | TOTP | Passkey | Purpose                                     | Status | Notes |
| :-: | :------------ | :---------------------------------- | :-------------------------------------- | :------------------------------- | :---------------------------: | :------: | :--: | :-----: | :------------------------------------------ | :----: | :---- |
| 1.  | skp1964-dev   | skp1964.dev@outlook.com             | `id_ed25519-skp1964.dev@outlook.com`    | `git: github: skp1964-dev`      | ✅ as skp1964-dev              | ✓ BW     |      | ✓ BW    | Default; personal projects & open source    | ✅ | Also alias: unselfish |
| 2.  | pilakkat1964  | pilakkat1964@gmail.com              | `id_ed25519-pilakkat1964@gmail.com`     | `git: github: pilakkat1964`     | ✅ as pilakkat1964             | ✓ BW     | ✓ BW | ✓ BW    | For formal use                              | ✅ | PAT entry exists |
| 3.  | pilakkat-shared | pilakkat.shared@gmail.com          | `id_ed25519-pilakkat.shared@gmail.com`  | `git: github: pilakkat-shared`  | ✅ as pilakkat-shared          | ✓ BW     |      | ✓ BW    | Shared with family                          | ✅ | SSH PW needs fixing |
| 4.  | skp64-pvtconfs | pilakkat+skp64-pvtconfs@gmail.com  | `id_ed25519-pilakkat+skp64-pvtconfs@gmail.com` | `git: github: skp64-pvtconfs` | ✅ as skp64-pvtconfs           | ✓ BW     |      | ✓ BW    | Config files, dotfiles                      | ✅ | |
| 5.  | skp1964-rust  | skp1964.rust@gmail.com              | `id_ed25519-skp1964.rust@gmail.com`     | `git: github: skp1964-rust`     | ✅ as skp1964-rust             | ✓ BW     | ✓ BW | ✓ BW    | Rust learning & experiments                 | ✅ | |
| 6.  | skp1964-sdr   | skp1964.sdr@gmail.com               | `id_ed25519-skp1964.sdr@gmail.com`      | `git: github: skp1964-sdr`      | ✅ as skp1964-sdr              | ✓ BW     | ✓ BW | ✓ BW    | SDR learning & experiments                  | ✅ | |
| 7.  | skp64-pvt01   | pilakkat+skp64-pvt01@gmail.com      | `id_ed25519-pilakkat+skp64-pvt01@gmail.com` | `git: github: skp64-pvt01`  | ✅ as skp64-pvt01              | ✓ BW     |      | ✓ BW    | Scratch pad                                 | ✅ | |
| 8.  | skp64prj-hub01 | skp64prj+skp64prj.hub01@gmail.com  | —                                       | `git: github: skp64prj-hub01`   | —                            | ✓ BW     | ✓ BW | ✓ BW    |                                             | ⚠️ | No SSH key configured |
| 9.  | skp64-def     | pilakkat-skp64-def@gmail.com       | `id_ed25519-pilakkat-skp64-def@gmail.com` | `git: github: skp64-def`      | ✅ as skp64-def                | ✓ BW     |      | ✓ BW    |                                             | ✅ | Key on disk, not in SSH config |
| 10. | newbyc333     | newbyc333@gmail.com                | `id_ed25519-newbyc333@gmail.com`        | `git: github: newbyc333`        | → as skp1964-dev (misassigned) | ✓ BW     |      |         |                                             | ⚠️ | SSH key registered to skp1964-dev, not newbyc333 |
| 11. | proteus       | —                                  | `id_rsa_proteus.cpi.3`                 | —                               | → as skp64-pvtconfs (misassigned) |        |      |         |                                             | ⚠️ | Key registered to skp64-pvtconfs; no BW creds |

## Gitlab Accounts

| No  | User Name        | Primary Email                         | SSH Key Filename                               | BW Record Name                       | SSH Verified                        | Password | TOTP | Passkey | Purpose                    | Status | Notes |
| :-: | :--------------- | :------------------------------------ | :-------------------------------------------- | :----------------------------------- | :---------------------------------: | :------: | :--: | :-----: | :------------------------- | :----: | :---- |
| 1.  | skpproj01        | skpdev19640101@gmail.com              | `id_ed25519-skpdev19640101@gmail.com`         | `git: gitlab: skpproj01`             | ✅ as skpproj01                     | ✓ BW     | ✓ BW | ✓ BW    |                            | ✅ | Display: SANTHOSH PILAKKAT |
| 2.  | skp64prj         | skp64prj@gmail.com                    | `id_ed25519-skp64prj@gmail.com`               | `git: gitlab: skp64prj`              | ✅ as skp64prj                      | ✓ BW     |      | ✓ BW    |                            | ✅ | Group: skp64prj-group |
| 3.  | skp64prj-shared01 | skp64prj+skp64prj.shared01@gmail.com | `id_ed25519-skp64prj+skp64prj.shared01@gmail.com` | `git: gitlab: skp64prj-shared01` | ✅ as skp64prj-shared01             | ✓ BW     |      | ✓ BW    | Pvt study, Coursera, Udemy | ✅ | |
| 4.  | pilakkat         | pilakkat@gmail.com                    | `id_ed25519-pilakkat@gmail.com`               | `git: gitlab: pilakkat`              | → as skp64prj-shared01 (misassigned) | ✓ BW     |      | ✓ BW    | gitlab.com                 | ⚠️ | Key registered to skp64prj-shared01 |
| 5.  | proteus.cpi.3    | proteus.cpi.3                         | `id_rsa_proteus.cpi.3`                       | `git: gitlab: proteus.cpi.3`        | → as skp64prj-shared01 (misassigned) | ✓ BW     |      | ✓ BW    | gitlab.com                 | ⚠️ | Key registered to skp64prj-shared01; has token in BW |
| 6.  | goofybits        | goofybits@gmail.com                   | `id_ed25519-goofybits@gmail.com`              | `git: gitlab: goofybits`            | → as skp64prj-shared01 (misassigned) | ✓ BW     |      | ✓ BW    | gitlab.com                 | ⚠️ | Key registered to skp64prj-shared01 |
| 7.  | skp64-dev        | goofybits+skp64.dev@gmail.com         | —                                             | `git: gitlab: skp64-dev`            | —                                 | ✓ BW     |      | ✓ BW    | gitlab.com                 | ⚠️ | No SSH key; Display: skp edev |
| 8.  | pilakkat @ freeddns | pilakkat@gmail.com / newbyc333@gmail.com | `id_rsa_proteus.cpi.3`                    | `git: gitlab.pilakkat.freeddns.org: <user>` | ⚠️ DNS unreachable          | ✓ BW     |      |         | Self-hosted GitLab         | ⚠️ | Host: gitlab.pilakkat.freeddns.org / :8443 |
| 9.  | root @ freeddns  | —                                     | —                                             | `git: gitlab.pilakkat.freeddns.org: root` | —                               | ✓ BW     |      |         | Self-hosted GitLab (admin) | ⚠️ | No SSH key |
| 10. | newbyc333 @ freeddns | newbyc333@gmail.com               | —                                             | `git: gitlab.pilakkat.freeddns.org: newbyc333` | —                           | ✓ BW     |      |         | Self-hosted GitLab         | ⚠️ | No SSH key |
| 11. | pilakkat @ ddns.net | pilakkat@gmail.com                 | —                                             | `git: pilakkat.ddns.net: <user>`   | —                                 | ✓ BW     |      |         | Self-hosted GitLab         | ⚠️ | No SSH key |
| 12. | pilakkat @ pilakkat.net | pilakkat@gmail.com             | —                                             | `git: gitlab.pilakkat.net: pilakkat@gmail.com` | —                           | ✓ BW     |      |         | Self-hosted GitLab         | ⚠️ | No SSH key |
| 13. | root @ gitlabee  | —                                     | —                                             | `git: gitlabee.pilakkat.freeddns.org: root` | —                               | ✓ BW     |      |         | Self-hosted GitLab EE      | ⚠️ | No SSH key |
| 14. | root @ 5ges      | —                                     | —                                             | `git: 5ges-gitlab.ngrn.a-star.edu.sg: root` | —                               | ✓ BW     |      |         | 5GES GitLab (ASTAR)        | ⚠️ | No SSH key |
