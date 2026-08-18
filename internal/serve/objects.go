package serve

// Object-level endpoints: tree, blob, and commit history
// (docs/gf-serve-api.md). Each request first Syncs the repo's local bare
// mirror, then answers with git plumbing against it — plaintext never leaves
// the machine.

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
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

	// The ref resolved against the server, but the commit it points at must also
	// be present in the local mirror before any git plumbing can read it. If it
	// isn't, the incremental Sync above missed it — the classic case is a vault
	// that was wiped and re-pushed, so packfile seqs restarted below our cached
	// last_seq and ListPackfiles reported nothing new. Rebuild from scratch and
	// re-check once. Without this the caller runs `git ls-tree <missing sha>`
	// and reports a misleading "path not found" for data that is really just
	// un-fetched.
	if !commitPresent(gitDir, sha) {
		slog.Info("serve: resolved commit missing from cache, rebuilding",
			slog.String("repo", owner+"/"+repo), slog.String("sha", sha))
		gitDir, err = opts.Materializer.Rebuild(owner, repo)
		if err != nil {
			writeRepoUpstreamError(w, "rebuilding repo cache", err)
			return "", "", true
		}
		if !commitPresent(gitDir, sha) {
			// The branch points at a commit no packfile contains, even after a
			// full re-fetch — a genuine server-side inconsistency, not a stale
			// cache. Say so rather than blaming the path.
			writeError(w, http.StatusBadGateway, "commit_unavailable",
				fmt.Sprintf("branch %q points at commit %s but no packfile on the server contains it", ref, sha))
			return "", "", true
		}
	}
	return gitDir, sha, false
}

// commitPresent reports whether the mirror at gitDir has the given commit
// object. `git cat-file -e` exits 0 when the object exists, non-zero otherwise.
func commitPresent(gitDir, sha string) bool {
	_, _, err := gitObj(gitDir, "cat-file", "-e", sha)
	return err == nil
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

// commitLogFormat is the --format= string both commit endpoints log with, so
// parseCommitRecords can read either one's output. %B (the full message) comes
// last because it is the only field that may contain newlines.
var commitLogFormat = "--format=" +
	strings.Join([]string{"%H", "%P", "%an", "%ae", "%aI", "%B"}, fieldSep) + recordSep

// parseCommitRecords decodes commitLogFormat output into commit entries,
// skipping any record that doesn't carry all six fields.
func parseCommitRecords(out string) []commitEntry {
	commits := []commitEntry{}
	for _, rec := range strings.Split(out, recordSep) {
		// git separates records with a newline of its own, which lands at the
		// front of every record after the first.
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
		commits = append(commits, commitEntry{
			SHA:     f[0],
			Parents: parents,
			Author:  commitAuthor{Name: f[2], Email: f[3]},
			Date:    f[4],
			Message: strings.TrimRight(f[5], "\n"),
		})
	}
	return commits
}

// oneCommit runs a `git log` expected to name exactly one commit and parses
// it, erroring when the command fails or matches nothing.
func oneCommit(gitDir string, args ...string) (commitEntry, error) {
	out, _, err := gitObj(gitDir, args...)
	if err != nil {
		return commitEntry{}, err
	}
	commits := parseCommitRecords(out)
	if len(commits) != 1 {
		return commitEntry{}, fmt.Errorf("expected one commit, got %d", len(commits))
	}
	return commits[0], nil
}

// readCommit loads one commit's metadata from the mirror. It errors when sha
// names something that isn't a commit — a tag or tree object, say.
func readCommit(gitDir, sha string) (commitEntry, error) {
	return oneCommit(gitDir, "log", "-1", commitLogFormat, sha, "--")
}

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
		out, _, err := gitObj(gitDir, "log",
			commitLogFormat,
			"--skip="+strconv.Itoa(skip),
			"-n", strconv.Itoa(limit+1),
			start, "--")
		if err != nil {
			// The ref/cursor resolved upstream but isn't a commit we hold —
			// treat as a bad cursor rather than an internal error.
			writeError(w, http.StatusNotFound, "ref_not_found", "cannot walk history from that point")
			return
		}

		resp := commitsResponse{Commits: parseCommitRecords(out)}
		if len(resp.Commits) > limit {
			resp.Commits = resp.Commits[:limit]
			resp.NextBefore = resp.Commits[limit-1].SHA
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

// ── Commit detail (diff) ─────────────────────────────────────────────────────

// The diff is always taken against the commit's FIRST parent (or the empty
// tree, for a root commit). Merge commits therefore show what the merge
// brought in relative to the branch it was made on, and the response's
// diff_against names the parent so the dashboard can say so.

// diffFile is one changed path in a commit's diff. Additions/Deletions are 0
// for binary files (git reports no line counts for them).
type diffFile struct {
	Path      string `json:"path"`
	OldPath   string `json:"old_path,omitempty"` // renames and copies only
	Status    string `json:"status"`             // see diffStatus
	Additions int    `json:"additions"`
	Deletions int    `json:"deletions"`
	Binary    bool   `json:"binary"`
	// Patch is the unified diff for this file alone, header included, exactly
	// as git renders it. Empty for binary files and whenever PatchOmitted is
	// set.
	Patch string `json:"patch,omitempty"`
	// PatchOmitted marks a file whose patch was dropped to keep the response
	// bounded — the stats above are still accurate.
	PatchOmitted bool `json:"patch_omitted,omitempty"`
}

type commitDetailResponse struct {
	commitEntry // sha, parents, author, date, message
	// DiffAgainst is the parent the diff was computed against; empty for a
	// root commit, whose diff is against the empty tree.
	DiffAgainst string `json:"diff_against,omitempty"`
	// Additions/Deletions are the totals across Files.
	Additions int        `json:"additions"`
	Deletions int        `json:"deletions"`
	Files     []diffFile `json:"files"`
	// FilesTruncated marks a diff too wide to return in full: Files holds the
	// first maxDiffFiles paths only.
	FilesTruncated bool `json:"files_truncated,omitempty"`
}

const (
	// maxDiffFiles caps how many changed paths one response describes.
	maxDiffFiles = 300
	// maxPatchBytes is the total patch budget for one response, and
	// maxFilePatchBytes the cap for any single file. Both exist so a
	// generated-file or vendor-drop commit can't hand the browser tens of
	// megabytes; the file list and its stats are returned regardless.
	maxPatchBytes     = 1 << 20   // 1 MiB
	maxFilePatchBytes = 128 << 10 // 128 KiB
)

func handleCommit(opts Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		gitDir, sha, done := syncAndResolve(w, r, opts)
		if done {
			return
		}

		meta, err := readCommit(gitDir, sha)
		if err != nil {
			// syncAndResolve already proved the object is present, so a
			// failure here means it isn't a commit (a tag or tree SHA).
			writeError(w, http.StatusNotFound, "ref_not_found",
				fmt.Sprintf("%s is not a commit in this vault", sha))
			return
		}

		resp := commitDetailResponse{commitEntry: meta, Files: []diffFile{}}
		// A root commit has no parent to diff against; --root makes git diff
		// it against the empty tree instead.
		spec := []string{"--root", meta.SHA}
		if len(meta.Parents) > 0 {
			resp.DiffAgainst = meta.Parents[0]
			spec = []string{meta.Parents[0], meta.SHA}
		}

		numstat, _, err := gitObj(gitDir, diffArgs(spec, "-z", "--numstat")...)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal", "computing the diff failed")
			return
		}
		nameStatus, _, err := gitObj(gitDir, diffArgs(spec, "-z", "--name-status")...)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal", "computing the diff failed")
			return
		}

		files := parseDiffFiles(numstat, nameStatus)
		if len(files) > maxDiffFiles {
			files, resp.FilesTruncated = files[:maxDiffFiles], true
		}

		// Patches are fetched one file at a time. A single -p run would be
		// cheaper, but a typechange emits two "diff --git" sections for one
		// numstat record, so splitting that stream risks pinning the wrong
		// patch on a file — and a wrong diff is worse than a slower one.
		budget := maxPatchBytes
		for i := range files {
			f := &files[i]
			resp.Additions += f.Additions
			resp.Deletions += f.Deletions
			if f.Binary {
				continue // "Binary files … differ" tells the dashboard nothing
			}
			if budget <= 0 {
				f.PatchOmitted = true
				continue
			}
			paths := []string{"--", ":(literal)" + f.Path}
			if f.OldPath != "" {
				// Both endpoints, so rename detection still pairs them.
				paths = append(paths, ":(literal)"+f.OldPath)
			}
			patch, _, err := gitObj(gitDir, append(diffArgs(spec, "-p"), paths...)...)
			if err != nil || len(patch) > maxFilePatchBytes || len(patch) > budget {
				f.PatchOmitted = true
				continue
			}
			f.Patch = patch
			budget -= len(patch)
		}
		resp.Files = files
		writeJSON(w, http.StatusOK, resp)
	}
}

// diffArgs builds a `git diff-tree` invocation for the given diff endpoints.
// The flags pin every setting that a user's git config could otherwise move:
// no external diff or textconv driver runs, colour stays off, and the context
// size is fixed, so the output is the same on every machine.
func diffArgs(spec []string, mode ...string) []string {
	args := []string{
		"diff-tree", "--no-commit-id", "-r", "--find-renames",
		"--no-ext-diff", "--no-textconv", "--no-color", "-U3",
	}
	args = append(args, mode...)
	return append(args, spec...)
}

// parseDiffFiles zips the -z --numstat and -z --name-status renderings of the
// same diff into one list. Line counts come from the former, the change kind
// from the latter, matched by path — both list every changed path exactly
// once, so a map keyed on the post-change path pairs them without relying on
// the two commands agreeing on order.
func parseDiffFiles(numstat, nameStatus string) []diffFile {
	status := map[string]string{}
	toks := splitNUL(nameStatus)
	for i := 0; i < len(toks); {
		letter := toks[i]
		i++
		if letter == "" {
			continue
		}
		// Renames and copies carry two paths ("R100\0old\0new"), everything
		// else one.
		n := 1
		if letter[0] == 'R' || letter[0] == 'C' {
			n = 2
		}
		if i+n > len(toks) {
			break // truncated output; nothing sane left to read
		}
		status[toks[i+n-1]] = letter
		i += n
	}

	files := []diffFile{}
	toks = splitNUL(numstat)
	for i := 0; i < len(toks); {
		rec := toks[i]
		i++
		if rec == "" {
			continue
		}
		// "<adds>\t<dels>\t<path>", or "<adds>\t<dels>\t" followed by
		// separate old and new path tokens for a rename or copy.
		parts := strings.SplitN(rec, "\t", 3)
		if len(parts) != 3 {
			continue
		}
		f := diffFile{Path: parts[2]}
		if f.Path == "" {
			if i+2 > len(toks) {
				break
			}
			f.OldPath, f.Path = toks[i], toks[i+1]
			i += 2
		}
		// git writes "-" for both counts of a binary file.
		if parts[0] == "-" || parts[1] == "-" {
			f.Binary = true
		} else {
			f.Additions, _ = strconv.Atoi(parts[0])
			f.Deletions, _ = strconv.Atoi(parts[1])
		}
		f.Status = diffStatus(status[f.Path])
		files = append(files, f)
	}
	return files
}

// splitNUL splits git's -z output into records, dropping the trailing empty
// field the final NUL leaves behind.
func splitNUL(out string) []string {
	out = strings.TrimSuffix(out, "\x00")
	if out == "" {
		return nil
	}
	return strings.Split(out, "\x00")
}

// diffStatus turns a --name-status letter into the name the dashboard shows.
// R and C carry a similarity score ("R100"), hence the prefix check. Unmerged
// and unknown states can't appear in a committed diff; they fall back to the
// neutral "modified".
func diffStatus(letter string) string {
	if letter != "" {
		switch letter[0] {
		case 'A':
			return "added"
		case 'D':
			return "deleted"
		case 'R':
			return "renamed"
		case 'C':
			return "copied"
		case 'T':
			return "typechanged"
		}
	}
	return "modified"
}

// ── Last commit per tree entry ───────────────────────────────────────────────

// treeCommitInfo is the slice of a commit the file explorer shows beside a
// row: enough to label it and link to its diff, without the parent list.
type treeCommitInfo struct {
	SHA     string       `json:"sha"`
	Author  commitAuthor `json:"author"`
	Date    string       `json:"date"`
	Message string       `json:"message"`
}

// treeCommitEntry is the newest commit that touched one path in a directory
// listing — the "last change" column of the file explorer, and the link that
// opens that commit's diff.
type treeCommitEntry struct {
	Path string `json:"path"`
	treeCommitInfo
}

type treeCommitsResponse struct {
	// Latest is the newest commit touching this directory at all — the header
	// row above the listing. For the repo root that is the ref's tip commit.
	Latest  *treeCommitInfo   `json:"latest,omitempty"`
	Entries []treeCommitEntry `json:"entries"`
}

// treeCommitWorkers bounds how many `git log` processes run at once. One walk
// per entry is a wider fan-out than one walk for the whole directory, but each
// `git log -1 <path>` stops at the first commit that touches its own path, and
// asking git the plain question per path beats stitching one interleaved
// --name-only stream back onto the right rows.
const treeCommitWorkers = 8

func handleTreeCommits(opts Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		gitDir, sha, done := syncAndResolve(w, r, opts)
		if done {
			return
		}
		dir := strings.Trim(r.URL.Query().Get("path"), "/")

		paths, err := listTreePaths(gitDir, sha, dir)
		if err != nil {
			writeError(w, http.StatusNotFound, "path_not_found",
				fmt.Sprintf("no directory at %q for this ref", dir))
			return
		}
		resp := treeCommitsResponse{Entries: lastCommits(gitDir, sha, paths)}
		// The directory's own newest commit. Asking git directly beats picking
		// the newest entry above by date: commit dates aren't monotonic across
		// a rebase or a skewed clock, and git orders history properly.
		if latest, err := lastCommitFor(gitDir, sha, dir); err == nil {
			resp.Latest = &latest
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

// listTreePaths returns the full paths of the entries directly inside dir
// (empty dir = repo root), in git's own order.
func listTreePaths(gitDir, sha, dir string) ([]string, error) {
	spec := sha
	if dir != "" {
		spec = sha + ":" + dir
	}
	out, _, err := gitObj(gitDir, "ls-tree", "--name-only", "-z", spec)
	if err != nil {
		return nil, err
	}
	paths := []string{}
	for _, name := range splitNUL(out) {
		if name == "" {
			continue
		}
		if dir != "" {
			name = dir + "/" + name
		}
		paths = append(paths, name)
	}
	return paths, nil
}

// lastCommits finds the newest commit touching each path, walking the paths
// concurrently. A path with no commit behind it — which shouldn't happen for a
// path that is in the tree — is left out rather than reported as an error: the
// explorer's other rows are still worth showing.
func lastCommits(gitDir, sha string, paths []string) []treeCommitEntry {
	found := make([]*treeCommitEntry, len(paths))
	sem := make(chan struct{}, treeCommitWorkers)
	var wg sync.WaitGroup
	for i, path := range paths {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			info, err := lastCommitFor(gitDir, sha, path)
			if err != nil {
				return
			}
			found[i] = &treeCommitEntry{Path: path, treeCommitInfo: info}
		}()
	}
	wg.Wait()

	entries := []treeCommitEntry{}
	for _, e := range found {
		if e != nil {
			entries = append(entries, *e)
		}
	}
	return entries
}

// lastCommitFor returns the newest commit touching path. A pathspec matches a
// directory and everything under it, so the same call answers for files and
// folders alike, and :(literal) keeps a path with glob characters in its name
// from matching siblings. An empty path means the whole tree — the ref's tip.
func lastCommitFor(gitDir, sha, path string) (treeCommitInfo, error) {
	args := []string{"log", "-1", commitLogFormat, sha, "--"}
	if path != "" {
		args = append(args, ":(literal)"+path)
	}
	c, err := oneCommit(gitDir, args...)
	if err != nil {
		return treeCommitInfo{}, err
	}
	return treeCommitInfo{
		SHA:     c.SHA,
		Author:  c.Author,
		Date:    c.Date,
		Message: c.Message,
	}, nil
}
