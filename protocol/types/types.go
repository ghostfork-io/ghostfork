package types

import "time"

// ── Users ────────────────────────────────────────────────────────────────────

// RegisterRequest creates a new account. PublicKey is the user's Ed25519
// public key (base64-std of the 32 raw bytes). The same key is used both
// for signing API requests (see docs/auth.md) and for wrapping repo keys
// via age (see docs/crypto.md).
type RegisterRequest struct {
	Username  string `json:"username"`
	PublicKey string `json:"public_key"`
}

type UserResponse struct {
	Username  string `json:"username"`
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
}

type UpdateRefRequest struct {
	CommitSHA string `json:"commit_sha"`
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
