package types

import "time"

// ── Users ────────────────────────────────────────────────────────────────────

// RegisterRequest creates a new account in one of two modes:
//
//   - Web registration: set Email + Password and leave PublicKey empty. The
//     server stores a bcrypt hash and creates the account with a NULL public
//     key, which the first 'gf login' fills in (see UploadPubKeyRequest).
//   - Legacy CLI registration: set PublicKey and leave Email/Password empty.
//     The same key is used both for signing API requests (see docs/auth.md) and
//     for wrapping repo keys via age (see docs/crypto.md).
type RegisterRequest struct {
	Username  string `json:"username"`
	PublicKey string `json:"public_key,omitempty"`
	Email     string `json:"email,omitempty"`
	Password  string `json:"password,omitempty"`
}

type UserResponse struct {
	Username  string `json:"username"`
	PublicKey string `json:"public_key"`
}

// LoginRequest authenticates a web-registered account by username + password.
// Used by 'gf login' to discover whether the account already has a public key
// before deciding to bootstrap one or prompt for key recovery.
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse reports whether the authenticated account already has a public
// key on file. When false, the client may upload one (first login). When true,
// the client must restore the original private key instead (key recovery).
type LoginResponse struct {
	Username     string `json:"username"`
	HasPublicKey bool   `json:"has_public_key"`
}

// UploadPubKeyRequest uploads the public key generated on first 'gf login' for
// a web-registered account. It is password-authenticated (not signed) because
// the account has no key yet. The server stores the key only if none is set —
// a second upload is rejected, so a stolen password cannot replace the key.
type UploadPubKeyRequest struct {
	Password  string `json:"password"`
	PublicKey string `json:"public_key"`
}

// ── Repos ─────────────────────────────────────────────────────────────────────

// CreateRepoRequest includes the encrypted repo key so the server can
// atomically create the repo and add the creator as first member. The repo
// owner is always the authenticated caller — there is no separate owner
// field on the wire.
type CreateRepoRequest struct {
	Name         string `json:"name"`
	EncryptedKey []byte `json:"encrypted_key"`
	// Owner optionally names an org slug to create the repo under (the caller
	// must be an admin of that org). Empty → a personal repo owned by the
	// authenticated caller. The encrypted key is always wrapped to the caller.
	Owner string `json:"owner,omitempty"`
}

// ── Refs ──────────────────────────────────────────────────────────────────────

type Ref struct {
	// Branch holds the full git ref name (refs/heads/<branch> or
	// refs/tags/<tag>), not a bare branch name — so tags and slash-containing
	// branch names round-trip. The JSON field stays "branch" for wire compat.
	Branch    string `json:"branch"`
	CommitSHA string `json:"commit_sha"`
}

type RefsResponse struct {
	Refs []Ref `json:"refs"`
	// DefaultBranch is the bare name of the repo's default branch — the one
	// clones should check out. Following GitHub's rule, the server sets it to
	// the first branch ever pushed. Empty for repos with no branches yet (or
	// ones predating default-branch support); clients fall back to "main".
	DefaultBranch string `json:"default_branch,omitempty"`
}

type UpdateRefRequest struct {
	CommitSHA string `json:"commit_sha"`
}

// SetRefsRequest commits a push — its final phase, following git-receive-pack.
// The server promotes the packfiles staged by this push (PackfileSeqs, uploaded
// quarantined) to committed, then updates each ref INDEPENDENTLY: a ref that
// can't be updated does not affect the others (normal git push semantics, not
// all-or-nothing). git has already applied the fast-forward/force rules
// client-side, so the refs here are ones git approved.
type SetRefsRequest struct {
	Refs []Ref `json:"refs"`
	// PackfileSeqs are the server-assigned sequence numbers of the packfiles
	// this push uploaded, to be promoted out of quarantine before the refs.
	PackfileSeqs []int64 `json:"packfile_seqs"`
}

// SetRefsResponse reports the outcome of SetRefsRequest. Failed lists the refs
// that could not be updated (empty when every ref landed); the rest succeeded.
type SetRefsResponse struct {
	Failed []RefFailure `json:"failed,omitempty"`
}

// RefFailure is one ref that could not be updated, with a client-safe reason
// the helper relays to git (and the user).
type RefFailure struct {
	Branch string `json:"branch"`
	Reason string `json:"reason"`
}

// ── Packfiles ─────────────────────────────────────────────────────────────────

// PackfileEntry is one item in a list response. The actual bytes are
// downloaded separately via GET /packfiles/:seq (application/octet-stream).
type PackfileEntry struct {
	Seq int64 `json:"seq"`
}

type PackfileListResponse struct {
	Packfiles []PackfileEntry `json:"packfiles"`
}

type UploadPackfileResponse struct {
	Seq int64 `json:"seq"`
}

// PackfileHashResponse reports the server's SHA-256 (and size) of one stored
// encrypted packfile blob, so a client (gf verify) can confirm the ciphertext
// it downloaded matches the server's record before decrypting it.
type PackfileHashResponse struct {
	Seq    int64  `json:"seq"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// ── Keys ──────────────────────────────────────────────────────────────────────

type KeyRequest struct {
	EncryptedKey []byte `json:"encrypted_key"`
}

type KeyResponse struct {
	EncryptedKey []byte `json:"encrypted_key"`
}

// ── Orgs & membership (see docs/billing-and-tiers.md) ───────────────────────

// CreateOrgRequest creates an org. The slug shares the flat namespace with
// usernames and must not collide. The authenticated caller becomes first admin.
type CreateOrgRequest struct {
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name,omitempty"`
}

// OrgResponse describes an org's billing state and size.
type OrgResponse struct {
	Slug          string     `json:"slug"`
	DisplayName   string     `json:"display_name"`
	PlanID        string     `json:"plan_id"`
	PlanExpiresAt *time.Time `json:"plan_expires_at,omitempty"`
	MemberCount   int        `json:"member_count"`
}

// Member is one org member and their role ("member" | "admin").
type Member struct {
	Username string    `json:"username"`
	Role     string    `json:"role"`
	JoinedAt time.Time `json:"joined_at"`
}

type MembersResponse struct {
	Members []Member `json:"members"`
}

// AddMemberRequest adds a user to an org. Role defaults to "member" when empty.
type AddMemberRequest struct {
	Username string `json:"username"`
	Role     string `json:"role,omitempty"`
}

// SetRoleRequest promotes or demotes a member ("member" | "admin").
type SetRoleRequest struct {
	Role string `json:"role"`
}
