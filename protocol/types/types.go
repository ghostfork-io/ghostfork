package types

// ── Users ────────────────────────────────────────────────────────────────────

type RegisterRequest struct {
	Username  string `json:"username"`
	PublicKey string `json:"public_key"`
}

type RegisterResponse struct {
	APIKey string `json:"api_key"`
}

type UserResponse struct {
	Username  string `json:"username"`
	PublicKey string `json:"public_key"`
}

// ── Repos ─────────────────────────────────────────────────────────────────────

// CreateRepoRequest includes the encrypted repo key so the server can
// atomically create the repo and add the creator as first member.
type CreateRepoRequest struct {
	Org          string `json:"org"`
	Name         string `json:"name"`
	EncryptedKey []byte `json:"encrypted_key"`
}

// ── Refs ──────────────────────────────────────────────────────────────────────

type Ref struct {
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
