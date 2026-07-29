package serve

// Object-level endpoints: tree, blob, and commit history
// (docs/gf-serve-api.md). Each request first Syncs the repo's local bare
// mirror, then answers with git plumbing against it — plaintext never leaves
// the machine.

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var shaRE = regexp.MustCompile(`^[0-9a-f]{40}$`)

// resolveRef turns the ?ref= parameter into a commit SHA. A 40-hex string
// passes through as-is (existence is checked by whichever git command runs
// next); anything else must name a branch or tag on the server — the server's
// refs are the source of truth, the local mirror keeps no refs at all.
func resolveRef(up Upstream, owner, repo, ref string) (string, error) {
	if shaRE.MatchString(ref) {
		return ref, nil
	}
	refs, _, err := up.GetRefs(owner, repo)
	if err != nil {
		return "", err
	}
	for _, r := range refs {
		if r.Branch == "refs/heads/"+ref || r.Branch == "refs/tags/"+ref || r.Branch == ref {
			return r.CommitSHA, nil
		}
	}
	return "", errRefNotFound
}

var errRefNotFound = fmt.Errorf("ref not found")

// syncAndResolve is the shared front half of every object endpoint: validate
// the ref parameter, bring the local mirror up to date, and resolve the ref.
// On failure it writes the error response and returns done=true.
func syncAndResolve(w http.ResponseWriter, r *http.Request, opts Options) (gitDir, sha string, done bool) {
	owner, repo := r.PathValue("owner"), r.PathValue("repo")
	ref := r.URL.Query().Get("ref")
	if ref == "" {
		writeError(w, http.StatusBadRequest, "ref_not_found", "missing required ?ref= parameter")
		return "", "", true
	}

	gitDir, err := opts.Materializer.Sync(owner, repo)
	if err != nil {
		if err == errBadName {
			writeError(w, http.StatusNotFound, "repo_not_found", "repo not found, or you don't have access to it")
			return "", "", true
		}
		writeRepoUpstreamError(w, "syncing repo", err)
		return "", "", true
	}

	sha, err = resolveRef(opts.Upstream, owner, repo, ref)
	if err != nil {
		if err == errRefNotFound {
			writeError(w, http.StatusNotFound, "ref_not_found",
				fmt.Sprintf("no branch or tag named %q", ref))
			return "", "", true
		}
		writeRepoUpstreamError(w, "resolving ref", err)
		return "", "", true
	}
	return gitDir, sha, false
}

// gitObj runs a git command against the bare mirror and returns stdout.
// stderr is captured for error classification, not shown to the browser.
func gitObj(gitDir string, args ...string) (stdout string, stderr string, err error) {
	cmd := exec.Command("git", args...)
	cmd.Env = append(os.Environ(), "GIT_DIR="+gitDir)
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err = cmd.Run()
	return out.String(), errb.String(), err
}

// ── Tree ─────────────────────────────────────────────────────────────────────

// treeEntry is one row of a directory listing. Size is present only for
// files.
type treeEntry struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Type string `json:"type"` // "file" | "dir" | "symlink" | "submodule"
	Size *int64 `json:"size,omitempty"`
}

type treeResponse struct {
	Entries []treeEntry `json:"entries"`
}

func handleTree(opts Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		gitDir, sha, done := syncAndResolve(w, r, opts)
		if done {
			return
		}
		dir := strings.Trim(r.URL.Query().Get("path"), "/")

		spec := sha
		if dir != "" {
			spec = sha + ":" + dir
		}
		out, errOut, err := gitObj(gitDir, "ls-tree", "-l", "-z", spec)
		if err != nil {
			// The ref was already resolved against the server, so a failure
			// here means the path doesn't exist (or isn't a directory) at
			// this commit.
			writeError(w, http.StatusNotFound, "path_not_found",
				fmt.Sprintf("no directory at %q for this ref", dir))
			_ = errOut
			return
		}

		resp := treeResponse{Entries: []treeEntry{}}
		for _, line := range strings.Split(strings.TrimRight(out, "\x00"), "\x00") {
			if line == "" {
				continue
			}
			// <mode> <type> <sha> <size>\t<name>
			meta, name, ok := strings.Cut(line, "\t")
			if !ok {
				continue
			}
			f := strings.Fields(meta)
			if len(f) != 4 {
				continue
			}
			e := treeEntry{Name: name, Path: name}
			if dir != "" {
				e.Path = dir + "/" + name
			}
			switch {
			case f[1] == "tree":
				e.Type = "dir"
			case f[1] == "commit":
				e.Type = "submodule"
			case f[0] == "120000":
				e.Type = "symlink"
			default:
				e.Type = "file"
				if n, err := strconv.ParseInt(f[3], 10, 64); err == nil {
					e.Size = &n
				}
			}
			resp.Entries = append(resp.Entries, e)
		}
		sort.Slice(resp.Entries, func(i, j int) bool {
			a, b := resp.Entries[i], resp.Entries[j]
			if (a.Type == "dir") != (b.Type == "dir") {
				return a.Type == "dir"
			}
			return strings.ToLower(a.Name) < strings.ToLower(b.Name)
		})
		writeJSON(w, http.StatusOK, resp)
	}
}

// ── Blob ─────────────────────────────────────────────────────────────────────

func handleBlob(opts Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		gitDir, sha, done := syncAndResolve(w, r, opts)
		if done {
			return
		}
		path := strings.Trim(r.URL.Query().Get("path"), "/")
		if path == "" {
			writeError(w, http.StatusBadRequest, "path_not_found", "missing required ?path= parameter")
			return
		}
		spec := sha + ":" + path

		// Type check first: cat-file -s would happily report a size for a
		// directory (tree) too, and a 200 with tree bytes is worse than a 404.
		typeOut, _, err := gitObj(gitDir, "cat-file", "-t", spec)
		if err != nil || strings.TrimSpace(typeOut) != "blob" {
			writeError(w, http.StatusNotFound, "path_not_found",
				fmt.Sprintf("no file at %q for this ref", path))
			return
		}
		sizeOut, _, err := gitObj(gitDir, "cat-file", "-s", spec)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal", "reading file failed")
			return
		}
		size, _ := strconv.ParseInt(strings.TrimSpace(sizeOut), 10, 64)

		cmd := exec.Command("git", "cat-file", "blob", spec)
		cmd.Env = append(os.Environ(), "GIT_DIR="+gitDir)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal", "reading file failed")
			return
		}
		if err := cmd.Start(); err != nil {
			writeError(w, http.StatusInternalServerError, "internal", "reading file failed")
			return
		}
		defer cmd.Wait() //nolint:errcheck // stream already committed to the client

		// Sniff the first 512 bytes for a best-guess Content-Type; the bytes
		// themselves are forwarded verbatim (binary passthrough per contract).
		head := make([]byte, 512)
		n, _ := io.ReadFull(stdout, head)
		w.Header().Set("Content-Type", http.DetectContentType(head[:n]))
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(head[:n])
		_, _ = io.Copy(w, stdout)
	}
}

// ── Commits ──────────────────────────────────────────────────────────────────

type commitAuthor struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

type commitEntry struct {
	SHA     string       `json:"sha"`
	Parents []string     `json:"parents"`
	Author  commitAuthor `json:"author"`
	Date    string       `json:"date"`
	Message string       `json:"message"`
}

type commitsResponse struct {
	Commits []commitEntry `json:"commits"`
	// NextBefore is the ?before= cursor for the next page; omitted when the
	// history is exhausted.
	NextBefore string `json:"next_before,omitempty"`
}

const (
	commitsDefaultLimit = 50
	commitsMaxLimit     = 200
	// Field/record separators for the git log format: ASCII unit/record
	// separators, which cannot appear in SHAs, emails, or ISO dates, and are
	// vanishingly unlikely in names or messages.
	fieldSep  = "\x1f"
	recordSep = "\x1e"
)

func handleCommits(opts Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		gitDir, sha, done := syncAndResolve(w, r, opts)
		if done {
			return
		}

		limit := commitsDefaultLimit
		if s := r.URL.Query().Get("limit"); s != "" {
			n, err := strconv.Atoi(s)
			if err != nil || n < 1 {
				writeError(w, http.StatusBadRequest, "not_found", "invalid ?limit= parameter")
				return
			}
			limit = min(n, commitsMaxLimit)
		}

		start := sha
		skip := 0
		if before := r.URL.Query().Get("before"); before != "" {
			if !shaRE.MatchString(before) {
				writeError(w, http.StatusBadRequest, "not_found", "invalid ?before= cursor")
				return
			}
			// "Strictly older than before": walk from the cursor, dropping
			// the cursor commit itself. Handles merge commits correctly,
			// unlike starting at before^.
			start, skip = before, 1
		}

		// Fetch one extra to learn whether another page exists.
		format := strings.Join([]string{"%H", "%P", "%an", "%ae", "%aI", "%B"}, fieldSep) + recordSep
		out, _, err := gitObj(gitDir, "log",
			"--format="+format,
			"--skip="+strconv.Itoa(skip),
			"-n", strconv.Itoa(limit+1),
			start, "--")
		if err != nil {
			// The ref/cursor resolved upstream but isn't a commit we hold —
			// treat as a bad cursor rather than an internal error.
			writeError(w, http.StatusNotFound, "ref_not_found", "cannot walk history from that point")
			return
		}

		resp := commitsResponse{Commits: []commitEntry{}}
		records := strings.Split(out, recordSep)
		for _, rec := range records {
			rec = strings.TrimLeft(rec, "\n")
			if rec == "" {
				continue
			}
			f := strings.SplitN(rec, fieldSep, 6)
			if len(f) != 6 {
				continue
			}
			parents := []string{}
			if f[1] != "" {
				parents = strings.Fields(f[1])
			}
			resp.Commits = append(resp.Commits, commitEntry{
				SHA:     f[0],
				Parents: parents,
				Author:  commitAuthor{Name: f[2], Email: f[3]},
				Date:    f[4],
				Message: strings.TrimRight(f[5], "\n"),
			})
		}
		if len(resp.Commits) > limit {
			resp.Commits = resp.Commits[:limit]
			resp.NextBefore = resp.Commits[limit-1].SHA
		}
		writeJSON(w, http.StatusOK, resp)
	}
}
