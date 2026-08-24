package serve

// The session endpoint behind the dashboard's "how this works" dialog. It
// answers "what exactly is running, and what has it actually moved?" with live
// values read at request time — the running process's own PID and port, the
// identity it authenticated as, the vault key it unwraps with, and byte counts
// measured by the decryption pipeline itself. Nothing here is a constant
// dressed up as a measurement: if a number is shown, something counted it.

import (
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/ghostfork/gf/internal/version"
)

// sessionVault is the part of the session that depends on which vault is open.
type sessionVault struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`
	// KeyFingerprint identifies the vault key this machine decrypts with,
	// without exposing it (see Materializer.KeyFingerprint).
	KeyFingerprint string `json:"key_fingerprint"`
	// Transfer counters for this vault since the helper started. All three are
	// legitimately zero when the vault was already materialized by an earlier
	// run — see CacheBytesOnDisk.
	PackfilesFetched        int64 `json:"packfiles_fetched"`
	CiphertextBytesFetched  int64 `json:"ciphertext_bytes_fetched"`
	PlaintextBytesDecrypted int64 `json:"plaintext_bytes_decrypted"`
	// CacheBytesOnDisk is how much decrypted data for this vault is already on
	// this machine, so a zero-fetch session can say why it fetched nothing
	// instead of showing a bare "0 B" that looks like a bug.
	CacheBytesOnDisk int64 `json:"cache_bytes_on_disk"`
}

type sessionResponse struct {
	Version string `json:"version"`
	// PID and Address are this exact process: a user can match them against
	// their own terminal and `lsof -i`, which is the point.
	PID     int    `json:"pid"`
	Address string `json:"address"`
	Port    int    `json:"port"`
	// Username is the identity the helper's signed requests authenticate as —
	// the Ed25519 key on this machine, NOT the dashboard's browser session.
	// The two are deliberately separate, and the dialog labels them as such.
	Username  string `json:"username"`
	ServerURL string `json:"server_url"`
	// StartedAt is when this helper process bound its port.
	StartedAt string `json:"started_at"`
	// UptimeSeconds saves the browser from clock-skew arithmetic against a
	// timestamp produced on the same machine.
	UptimeSeconds int64        `json:"uptime_seconds"`
	Vault         sessionVault `json:"vault"`
	// PlaintextBytesSentToServer is the number every other field exists to
	// make believable. It is structurally zero, not merely observed to be: the
	// interfaces this package holds over the API client (Upstream,
	// MaterializeUpstream) expose reads only, so no code path here can upload
	// anything at all, let alone plaintext. TestServeUpstreamIsReadOnly fails
	// if an upload method is ever added to either.
	PlaintextBytesSentToServer int64 `json:"plaintext_bytes_sent_to_server"`
}

func handleSession(opts Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		owner, repo := r.PathValue("owner"), r.PathValue("repo")

		fingerprint, err := opts.Materializer.KeyFingerprint(owner, repo)
		if err != nil {
			if err == errBadName {
				writeError(w, http.StatusNotFound, "repo_not_found",
					"repo not found, or you don't have access to it")
				return
			}
			writeRepoUpstreamError(w, "reading vault key fingerprint", err)
			return
		}
		stats := opts.Materializer.Stats(owner, repo)

		port := 0
		if _, p, err := net.SplitHostPort(opts.Addr); err == nil {
			port, _ = strconv.Atoi(p)
		}

		writeJSON(w, http.StatusOK, sessionResponse{
			Version:       version.String(),
			PID:           os.Getpid(),
			Address:       opts.Addr,
			Port:          port,
			Username:      opts.Username,
			ServerURL:     opts.ServerURL,
			StartedAt:     opts.StartedAt.Format(time.RFC3339),
			UptimeSeconds: int64(time.Since(opts.StartedAt).Seconds()),
			Vault: sessionVault{
				Owner:                   owner,
				Name:                    repo,
				KeyFingerprint:          fingerprint,
				PackfilesFetched:        stats.PackfilesFetched,
				CiphertextBytesFetched:  stats.CiphertextBytes,
				PlaintextBytesDecrypted: stats.PlaintextBytes,
				CacheBytesOnDisk:        opts.Materializer.CacheBytes(owner, repo),
			},
			PlaintextBytesSentToServer: 0,
		})
	}
}
