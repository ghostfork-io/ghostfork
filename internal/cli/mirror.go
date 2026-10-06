package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ghostfork/gf/internal/config"
)

var mirrorCmd = &cobra.Command{
	Use:   "mirror <source-url> [<vault>]",
	Short: "Mirror an existing git repo (e.g. on GitHub) into an encrypted vault",
	Long: `Mirror every branch and tag of an existing git repository — typically one
on GitHub — into an encrypted Ghostfork vault. The source stays the source
of truth: keep working against it as normal, and re-run the same command
whenever you want the vault brought up to date.

Everything happens on this machine. gf fetches the source with your
existing git credentials (SSH keys, a credential helper, or
'gh auth setup-git'), then pushes through the same client-side encryption
as 'git push' to a gf:// remote. Ghostfork never contacts the source and
never sees your source credentials or plaintext.

<vault> defaults to the source repository's name. If the vault does not
exist yet it is created, owned by you. A local mirror cache is kept in the
gf config directory so re-syncs fetch and push only what changed.

Mirroring is one-way. Branches are force-updated to match the source, so
anything pushed to the vault directly is overwritten on the next sync.
Branches and tags deleted from the source are NOT yet deleted from the
vault; gf lists them so you know. GitHub pull-request refs (refs/pull/*)
are not mirrored.`,
	Example: `  # Mirror a GitHub repo into a vault named after it ("myproject")
  gf mirror git@github.com:alice/myproject.git

  # Mirror into a vault with a different name
  gf mirror https://github.com/alice/myproject myproject-mirror

  # Sync again later: run the same command
  gf mirror git@github.com:alice/myproject.git`,
	Args: cobra.RangeArgs(1, 2),
	RunE: runMirror,
}

// mirrorRemote is the name of the gf:// remote inside a mirror cache; the
// source is always "origin".
const mirrorRemote = "ghostfork"

// mirrorRefspecs are the refs a mirror carries: branches and tags, nothing
// else. GitHub also serves refs/pull/* to a plain `clone --mirror`; those are
// GitHub-internal and deliberately left out. The leading "+" makes every
// update a force update — the source is canonical.
var mirrorRefspecs = []string{"+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*"}

func runMirror(cmd *cobra.Command, args []string) error {
	source := args[0]
	if strings.HasPrefix(source, "gf://") {
		return fmt.Errorf("%s is already a Ghostfork vault — gf mirror copies a repo from another host (e.g. GitHub) into Ghostfork", source)
	}
	vaultArg := ""
	if len(args) == 2 {
		vaultArg = args[1]
	} else {
		name, err := vaultNameFromURL(source)
		if err != nil {
			return err
		}
		vaultArg = name
	}

	sess, err := loadSession()
	if err != nil {
		return err
	}
	owner, vault, err := parseRepoArg(vaultArg, sess.cfg.Username)
	if err != nil {
		return err
	}
	shown := redactURL(source)
	slog.Debug("mirror start", slog.String("source", shown), slog.String("vault", owner+"/"+vault))

	out, errOut := cmd.OutOrStdout(), cmd.ErrOrStderr()

	if err := ensureVault(sess, owner, vault); err != nil {
		return err
	}

	cacheDir, err := mirrorCacheDir(owner, vault)
	if err != nil {
		return err
	}
	if err := prepareMirrorCache(cacheDir, source, "gf://"+owner+"/"+vault); err != nil {
		return err
	}

	fmt.Fprintf(out, "\nFetching %s…\n", shown)
	if err := runGitInteractive(cmd, cacheDir, "fetch", "--prune", "origin"); err != nil {
		return fmt.Errorf("fetching %s: %w", shown, err)
	}
	setMirrorHead(cacheDir)

	local, err := mirrorRefs(cacheDir)
	if err != nil {
		return err
	}
	if len(local) == 0 {
		return fmt.Errorf("%s has no branches or tags to mirror", shown)
	}

	fmt.Fprintf(out, "Encrypting and pushing to gf://%s/%s…\n", owner, vault)
	pushArgs := append([]string{"push", mirrorRemote}, mirrorRefspecs...)
	if err := runGitInteractive(cmd, cacheDir, pushArgs...); err != nil {
		return fmt.Errorf("pushing to gf://%s/%s: %w", owner, vault, err)
	}

	// Flag the vault as a mirror so the dashboard can warn against pushing to
	// it directly. Only the boolean goes to the server, never the source URL.
	// The mirror itself already succeeded, so a failure here is a warning.
	if err := sess.client.SetMirror(owner, vault, true); err != nil {
		slog.Warn("setting mirror flag failed", slog.Any("err", err))
		fmt.Fprintf(errOut, "\nwarning: the vault was synced, but marking it as a mirror on the dashboard failed: %v\n", err)
	}

	// Refs the vault still has but the source no longer does. The helper
	// can't delete refs yet, so all we can do is say so.
	if serverRefs, _, err := sess.client.GetRefs(owner, vault); err == nil {
		var stale []string
		for _, r := range serverRefs {
			if _, ok := local[r.Branch]; !ok {
				stale = append(stale, r.Branch)
			}
		}
		if len(stale) > 0 {
			sort.Strings(stale)
			fmt.Fprintf(errOut, "\nnote: %d ref(s) in the vault no longer exist in the source and were left\n", len(stale))
			fmt.Fprintf(errOut, "in place (deleting refs from a vault is not supported yet):\n")
			for _, r := range stale {
				fmt.Fprintf(errOut, "    %s\n", r)
			}
		}
	} else {
		slog.Debug("listing vault refs after mirror failed", slog.Any("err", err))
	}

	branches, tags := 0, 0
	for r := range local {
		if strings.HasPrefix(r, "refs/tags/") {
			tags++
		} else {
			branches++
		}
	}
	slog.Info("mirror complete", slog.String("vault", owner+"/"+vault),
		slog.Int("branches", branches), slog.Int("tags", tags))

	fmt.Fprintf(out, "\nMirrored %s → gf://%s/%s (%d branch(es), %d tag(s))\n\n", shown, owner, vault, branches, tags)
	fmt.Fprintf(out, "The source stays the source of truth. To sync again, re-run:\n\n")
	fmt.Fprintf(out, "    gf mirror %s %s/%s\n\n", source, owner, vault)
	fmt.Fprintf(out, "Don't push to this vault directly — the next sync overwrites it.\n\n")
	return nil
}

// ensureVault makes sure the caller can push to owner/vault, creating it when
// it is the caller's own and does not exist yet.
func ensureVault(sess *session, owner, vault string) error {
	repos, err := sess.client.ListMyRepos()
	if err != nil {
		return fmt.Errorf("listing your vaults: %w", err)
	}
	for _, r := range repos {
		if r.Owner == owner && r.Name == vault {
			return nil
		}
	}
	if owner != sess.cfg.Username {
		return fmt.Errorf("you are not a member of vault %s/%s — ask its owner to run 'gf add-user', or mirror into a vault of your own", owner, vault)
	}
	if err := createVault(sess, vault); err != nil {
		return err
	}
	slog.Info("vault created for mirror", slog.String("vault", owner+"/"+vault))
	return nil
}

// mirrorCacheDir is where the bare mirror of owner/vault lives:
// <gf config dir>/mirrors/<owner>/<vault>.git. One cache per vault, because
// the helper's state is kept per git dir.
func mirrorCacheDir(owner, vault string) (string, error) {
	for _, part := range []string{owner, vault} {
		if part == "." || part == ".." || strings.ContainsAny(part, `/\`) {
			return "", fmt.Errorf("invalid vault name %q", owner+"/"+vault)
		}
	}
	return filepath.Join(config.DefaultDir(), "mirrors", owner, vault+".git"), nil
}

// prepareMirrorCache creates the bare cache on first use, wired to fetch
// branches and tags from source and push to vaultURL. On later runs it checks
// the cache still points at the same source, so two different repos are never
// mixed into one vault by accident.
func prepareMirrorCache(dir, source, vaultURL string) error {
	if _, err := os.Stat(dir); err == nil {
		got, err := runGit(dir, nil, "config", "--get", "remote.origin.url")
		if err != nil {
			return fmt.Errorf("reading mirror cache %s: %w", dir, err)
		}
		if got = strings.TrimSpace(got); got != source {
			return fmt.Errorf("this vault is already mirrored from %s, not %s\n(local mirror cache: %s)",
				redactURL(got), redactURL(source), dir)
		}
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("checking mirror cache: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return fmt.Errorf("creating mirror cache: %w", err)
	}
	steps := [][]string{
		{"config", "remote.origin.url", source},
		{"config", "remote.origin.fetch", mirrorRefspecs[0]},
		{"config", "--add", "remote.origin.fetch", mirrorRefspecs[1]},
		{"config", "remote." + mirrorRemote + ".url", vaultURL},
	}
	if out, err := exec.Command("git", "init", "--bare", "--quiet", dir).CombinedOutput(); err != nil {
		return fmt.Errorf("creating mirror cache: %w: %s", err, strings.TrimSpace(string(out)))
	}
	for _, s := range steps {
		if _, err := runGit(dir, nil, s...); err != nil {
			os.RemoveAll(dir) //nolint:errcheck // best-effort: a half-configured cache would fail the next run
			return fmt.Errorf("configuring mirror cache: %w", err)
		}
	}
	slog.Debug("mirror cache created", slog.String("dir", dir))
	return nil
}

// setMirrorHead points the cache's HEAD at the source's default branch, so
// the helper offers that branch first and a fresh vault gets the same default
// branch as the source. Best-effort: a source that doesn't advertise HEAD
// just leaves the vault's default to the helper's usual rule.
func setMirrorHead(dir string) {
	out, err := runGit(dir, nil, "ls-remote", "--symref", "origin", "HEAD")
	if err != nil {
		slog.Debug("reading source HEAD failed", slog.Any("err", err))
		return
	}
	for line := range strings.SplitSeq(out, "\n") {
		ref, ok := strings.CutPrefix(line, "ref: ")
		if !ok {
			continue
		}
		ref, _, _ = strings.Cut(ref, "\t")
		if _, err := runGit(dir, nil, "symbolic-ref", "HEAD", ref); err != nil {
			slog.Debug("setting mirror HEAD failed", slog.Any("err", err))
		}
		return
	}
}

// mirrorRefs returns the branch and tag refs in the cache.
func mirrorRefs(dir string) (map[string]struct{}, error) {
	out, err := runGit(dir, nil, "for-each-ref", "--format=%(refname)", "refs/heads", "refs/tags")
	if err != nil {
		return nil, fmt.Errorf("listing mirrored refs: %w", err)
	}
	refs := map[string]struct{}{}
	for r := range strings.FieldsSeq(out) {
		refs[r] = struct{}{}
	}
	return refs, nil
}

// runGitInteractive runs a network git command against dir with the terminal
// attached, so git's progress shows and credential prompts for the source
// work as they would for a plain `git fetch`.
func runGitInteractive(cmd *cobra.Command, dir string, args ...string) error {
	c := exec.Command("git", append([]string{"--git-dir=" + dir}, args...)...)
	c.Stdin = os.Stdin
	c.Stdout = cmd.OutOrStdout()
	c.Stderr = cmd.ErrOrStderr()
	return c.Run()
}

// vaultNameFromURL derives a vault name from a git URL's last path segment:
// "git@github.com:alice/proj.git" and "https://github.com/alice/proj" both
// give "proj".
func vaultNameFromURL(source string) (string, error) {
	s := source
	// For scheme URLs only the path names the repo — never fall back to the
	// host ("https://github.com/" must not become a vault called github.com).
	if u, err := url.Parse(source); err == nil && u.Scheme != "" && u.Host != "" {
		s = u.Path
	}
	s = strings.TrimRight(s, "/")
	s = strings.TrimSuffix(s, ".git")
	if i := strings.LastIndexAny(s, "/:"); i >= 0 {
		s = s[i+1:]
	}
	if s == "" || s == "." || s == ".." {
		return "", fmt.Errorf("can't derive a vault name from %q — pass one: gf mirror <source-url> <vault>", source)
	}
	return s, nil
}

// redactURL hides credentials embedded in an https URL
// (https://user:token@github.com/...) before it is printed or logged.
func redactURL(source string) string {
	u, err := url.Parse(source)
	if err != nil || u.User == nil {
		return source
	}
	u.User = url.User("***")
	return u.String()
}
