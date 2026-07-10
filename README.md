# Ghostfork

**Zero-trust Git hosting. Your code is encrypted client-side before it leaves your machine. The server never has plaintext access.**

---

## What it is

Ghostfork is a Git hosting layer that removes the server from your trust model. When you push code, it is encrypted on your machine before transmission. The server stores ciphertext. It holds encrypted keys it cannot use. If the server is compromised, breached, subpoenaed, or misconfigured, your file contents, file names, and commit messages are not exposed — there is nothing readable to take.

Think of it as a safety deposit box where the bank never has a copy of your key. The box is theirs. The contents are yours.

---

## Why it exists

Self-hosted Git solves the vendor trust problem. It does not solve the server trust problem. Your Gitea or GitLab instance still holds plaintext code. A compromised server, a rogue admin, or a misconfigured permission is all it takes. Most teams respond to this with policy. Ghostfork responds to it with architecture.

Plaintext exposure is removed at the structural level, not the compliance level.

---

## How it works

You register an account on the web. On your first `gf login`, your machine generates an Ed25519 keypair locally — the private key never leaves your control. Before a push, the `gf` helper encrypts repository contents client-side (XChaCha20-Poly1305 for content, age for key wrapping). The server receives and stores only ciphertext. When you pull or clone, the helper fetches ciphertext and decrypts locally.

The server is a blind courier. It cannot read what it carries.

```
[your machine]  ->  encrypt  ->  [ghostfork server]  ->  store ciphertext
[your machine]  <-  decrypt  <-  [ghostfork server]  <-  fetch ciphertext
```

There is no server-side decryption path. You can prove this to yourself at any time: `gf verify` downloads a stored blob, shows you it is ciphertext, and demonstrates that only your local key opens it.

---

## Quick start

```bash
# 1. Create an account (web registration; the CLI never sees your password hash)
#    https://app.ghostfork.io/register

# 2. Authenticate this machine — generates your keypair locally on first login
gf login --server https://app.ghostfork.io --username alice

# 3. Create an encrypted repo on the server
gf init-repo my-project

# 4. Use it as a normal git remote — encryption happens transparently
git remote add origin gf://alice/my-project
git push -u origin main

# 5. Prove the server only stored ciphertext
gf verify alice/my-project

# Grant a teammate access (they need their own account)
gf add-user my-project bob
```

Everything after `gf login` is plain Git. Your editors, hooks, branches, and workflows don't change.

---

## Installation

Grab a binary from [Releases](https://github.com/ghostfork-io/ghostfork/releases), or build from source. Git itself is the only other requirement.

**macOS / Linux (binary):**

```bash
# pick your platform: gf-darwin-arm64, gf-darwin-amd64, gf-linux-amd64
curl -sSLo gf https://github.com/ghostfork-io/ghostfork/releases/latest/download/gf-linux-amd64
chmod +x gf
mkdir -p ~/.local/bin && mv gf ~/.local/bin/gf
# git discovers gf:// remotes through this name:
ln -sf ~/.local/bin/gf ~/.local/bin/git-remote-gf
```

Make sure `~/.local/bin` is on your `PATH`.

**macOS / Linux (from source, requires Go 1.25+):**

```bash
git clone https://github.com/ghostfork-io/ghostfork.git
cd ghostfork
make install     # installs gf + the git-remote-gf link to ~/.local/bin, updates PATH
```

**Windows:**

Download `gf-windows-amd64.exe` from Releases, then in a folder on your `PATH`:

```powershell
copy gf-windows-amd64.exe gf.exe
copy gf-windows-amd64.exe git-remote-gf.exe
```

The `git-remote-gf` name is how Git finds the helper for `gf://` URLs — it must sit next to `gf` on your `PATH`. No daemon, no background service: Git invokes the helper only for pushes and pulls.

---

## Commands

| Command | What it does |
| --- | --- |
| `gf login` | Authenticates this machine with a Ghostfork server; first login generates your keypair locally |
| `gf logout` | Backs up your key, then clears this machine's session |
| `gf status` | Shows which account is logged in on this machine |
| `gf init-repo <name>` | Creates a new encrypted repository on the server |
| `gf add-user <repo> <username>` | Grants a user access — the repo key is re-encrypted to their public key, on your machine |
| `gf remove-user <repo> <username>` | Revokes a user's access |
| `gf switch-user <username>` | Switches the active local account to a previously parked one |
| `gf key export` | Exports your private key to move your account to another machine |
| `gf verify <owner>/<repo>` | Downloads a stored blob and proves it is ciphertext only you can open |

Run `gf <command> --help` for details on any of them.

---

## What the server can and cannot see

Honesty matters more than a slogan, so here is the precise boundary.

**The server never sees:** file contents, file names, directory structure inside commits, or commit messages. These are encrypted on your machine with a key the server does not hold.

**The server does see:** repository names, branch and tag names, usernames and who has access to what, and the timing and size of pushes and pulls. That is the metadata required to route and store your ciphertext.

**One more thing to know:** your private key *is* your account. It never leaves your machine, which also means we cannot recover it. `gf key export` exists so you can back it up — do that.

---

## Status

Ghostfork is in early access. The `gf` helper (this repository) is open source; the server component is not.

**Working now:**

- The full CLI: login, repos, access grants, key management, verification
- Push, pull, and clone over encrypted transport — plain Git on the surface
- Multi-user access via client-side key wrapping
- Web dashboard: registration, account overview, plan and usage

**Coming next:**

- Browse repo contents in the browser — decrypted locally by a helper on your machine, never on the server
- Richer team and organisation management
- Audit log

This is not a prototype. It is not yet feature-complete.

---

## Early access

The waitlist is at [ghostfork.io](https://ghostfork.io). If you have a specific use case or want to talk through the trust model, reach out at hello@ghostfork.io.
