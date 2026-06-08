# Ghostfork

**Zero-trust Git hosting. Your code is encrypted client-side before it leaves your machine. The server never has plaintext access.**

---

## What it is

Ghostfork is a Git hosting layer that removes the server from your trust model. When you push code, it is encrypted on your machine before transmission. The server stores ciphertext. It holds encrypted keys it cannot use. If the server is compromised, breached, subpoenaed, or misconfigured, an attacker gets noise.

Think of it as a safety deposit box where the bank never has a copy of your key. The box is theirs. The contents are yours.

---

## Why it exists

Self-hosted Git solves the vendor trust problem. It does not solve the server trust problem. Your Gitea or GitLab instance still holds plaintext code. A compromised server, a rogue admin, or a misconfigured permission is all it takes. Most teams respond to this with policy. Ghostfork responds to it with architecture.

Plaintext exposure is removed at the structural level, not the compliance level.

---

## How it works

Key generation happens locally. Your machine generates an encryption key that never leaves your control unencrypted. Before a push, the `gf` helper encrypts repository contents client-side. The server receives and stores only ciphertext. When you clone on a new machine, the helper fetches ciphertext and decrypts locally.

The server is a blind courier. It cannot read what it carries.

```
[your machine]  ->  encrypt  ->  [ghostfork server]  ->  store ciphertext
[new machine]   <-  decrypt  <-  [ghostfork server]  <-  fetch ciphertext
```

There is no server-side decryption path.

---

## The demo

```
# Authenticate
gf login

# Initialise a new encrypted repo
gf init-repo my-project

# Add the remote and push — encryption happens transparently
git remote add origin gf://<owner>/my-project
git push origin main

# SSH into the server and look at what is stored
# Encrypted blobs. Not your code.

# Clone on a fresh machine
git clone gf://<owner>/my-project
# gf decrypts locally on the way out
```

> Demo video coming. The commands above are the full flow.
> 

---

## Installation

```
# macOS / Linux
curl -sSL https://ghostfork.io/install.sh | sh

# Or download the binary directly
# https://ghostfork.io/releases
```

Requires only the `gf` binary. No daemon, no background service.

---

## Commands

| Command | What it does |
| --- | --- |
| `gf login` | Authenticates your machine with the Ghostfork server and sets up local key material |
| `gf init-repo <name>` | Initialises a new encrypted repository and registers it server-side |
| `gf add-user <repo> <pubkey>` | Grants another user access to a repository by adding their public key |

---

## Status

Ghostfork is in early access. V1 is terminal-based. No web interface yet. The `gf` helper is open source. The server component is not.

**Working now:**

- `gf login`, `gf init-repo`, `gf add-user`
- Push and clone over encrypted transport
- Multi-user access via key grants

**Coming next:**

- Web interface with browser-side decryption
- Team and organisation management
- Audit log

This is not a prototype. It is not yet feature-complete.

---
 
## Early access
 
The waitlist is at [ghostfork.io](https://ghostfork.io). If you have a specific use case or want to talk through the trust model, reach out at hello@ghostfork.io.
