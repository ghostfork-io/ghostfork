package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/ghostfork/gf/crypto"
	"github.com/ghostfork/gf/internal/apiclient"
	"github.com/ghostfork/gf/internal/config"
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with a Ghostfork server",
	Long: `Register a new account on a Ghostfork server, or recover an existing
account on a new machine.

What happens depends on what's on disk and which flags are set:

  1. No identity file, no --recover → register a new account.
     A fresh Ed25519 keypair is generated locally, the public key is
     registered with the server, and the private key is written to
     ~/.config/gf/identity.ed25519 (0600).

  2. --recover flag → paste your existing private key.
     gf prompts for the private key (hidden input on a TTY, or reads
     one line from stdin when piped). The key is verified against the
     server before anything is written to disk. Refused if an identity
     file already exists locally.

  3. Identity file present (copied from another machine), no config
     → automatic recovery without --recover. Same verification, same
     outcome.

  4. Identity file and config present, matching the args → no-op.

  5. Identity file and config present, different args → refused.
     Delete ~/.config/gf/ first if you really want to start over.

There is no API token to keep secret: every request is signed live by
your private key. Losing the identity file is equivalent to losing the
account — V1 has no key recovery mechanism. Back up
identity.ed25519 to a safe place.`,
	Example: `  # First login on a new machine
  gf login --server https://api.example.com --username alice

  # Recover on a new machine via terminal paste (key is hidden as you type)
  gf login --server https://api.example.com --username alice --recover

  # Recover non-interactively (e.g. from a CI secret)
  echo "$BACKED_UP_KEY" | gf login --server https://api.example.com --username alice --recover

  # Idempotent check (already logged in)
  gf login --server https://api.example.com --username alice`,
	RunE: runLogin,
}

func init() {
	loginCmd.Flags().String("server", "", "server URL (required)")
	loginCmd.Flags().String("username", "", "username to register or log in as (required)")
	loginCmd.Flags().Bool("recover", false, "recover an existing account by providing the private key on stdin (hidden prompt on a TTY)")
	loginCmd.MarkFlagRequired("server")
	loginCmd.MarkFlagRequired("username")
}

func runLogin(cmd *cobra.Command, _ []string) error {
	serverURL, _ := cmd.Flags().GetString("server")
	username, _ := cmd.Flags().GetString("username")
	doRecover, _ := cmd.Flags().GetBool("recover")

	// Reject a malformed --server before touching disk or the network, so the
	// user gets an immediate, actionable error instead of a cryptic transport
	// failure (or a hang) once a request is sent.
	if err := apiclient.ValidateBaseURL(serverURL); err != nil {
		return err
	}

	identityPath := config.DefaultIdentityPath()
	cfgPath := config.DefaultPath()

	slog.Debug("login start",
		slog.String("server", serverURL),
		slog.String("username", username),
		slog.Bool("recover", doRecover),
		slog.String("identity_path", identityPath),
		slog.String("config_path", cfgPath),
	)

	// --recover: user is pasting an existing private key. Handle this before
	// the other branches because it must refuse if an identity file already
	// exists (we never want to clobber a working key with one from stdin).
	if doRecover {
		return recoverFromInput(cmd, serverURL, username, identityPath, cfgPath)
	}

	// If an identity file is already on disk, this machine has either been
	// logged in before, or the user has copied an existing identity over to
	// recover their account. Decide which based on whether the saved config
	// matches the requested credentials.
	if _, err := os.Stat(identityPath); err == nil {
		cfg, cfgErr := config.Load(cfgPath)
		if cfgErr != nil {
			// Identity present but no usable config — file-copy recovery
			// path. Verify the key actually belongs to <username> on
			// <server> before writing the config.
			return recoverFromFile(cmd, serverURL, username, identityPath, cfgPath)
		}
		if cfg.Username == username && cfg.ServerURL == serverURL {
			fmt.Fprintf(cmd.OutOrStdout(), "\nAlready logged in as %s on %s.\n\n", username, serverURL)
			return nil
		}
		return fmt.Errorf(
			"this machine is already logged in as %s on %s.\n"+
				"To log in as a different user, use a different machine or delete\n"+
				"%s first (destructive — see CLAUDE.md threat model on key loss)",
			cfg.Username, cfg.ServerURL, identityPath)
	}

	// No identity yet — fresh login. Generate the keypair in memory and
	// register with the server before writing anything to disk, so a Register
	// failure leaves no local state to clean up.
	slog.Debug("generating new identity")
	id, err := crypto.GenerateIdentity()
	if err != nil {
		return fmt.Errorf("generating identity: %w", err)
	}

	slog.Debug("registering with server", slog.String("server", serverURL))
	// Surface the key being sent so a `-v` run can confirm exactly which
	// identity is registered (e.g. when juggling several accounts). The public
	// key is not secret, so logging it — and its fingerprint — is safe.
	slog.Debug("sending public key to server",
		slog.String("fingerprint", id.PublicKeyFingerprint()),
		slog.String("public_key", id.PublicKeyString()))
	client := apiclient.New(serverURL)
	if err := client.Register(username, id.PublicKeyString()); err != nil {
		// An unreachable server already carries a clear, user-facing message;
		// don't bury it under a "registering with server:" prefix.
		var unreachable *apiclient.UnreachableError
		if errors.As(err, &unreachable) {
			return err
		}
		return fmt.Errorf("registering with server: %w", err)
	}
	slog.Debug("server registration complete")

	if err := crypto.SaveIdentity(identityPath, id); err != nil {
		return fmt.Errorf("saving identity: %w", err)
	}

	cfg := &config.Config{
		Username:  username,
		ServerURL: serverURL,
	}
	if err := config.Save(cfgPath, cfg); err != nil {
		return fmt.Errorf("saving config: %w", err)
	}
	slog.Debug("identity and config written",
		slog.String("identity_path", identityPath),
		slog.String("config_path", cfgPath),
	)

	fmt.Fprintf(cmd.OutOrStdout(), "\nLogged in as %s on %s.\n", username, serverURL)
	fmt.Fprintf(cmd.OutOrStdout(), "Identity written to %s\n\n", identityPath)
	fmt.Fprintf(cmd.OutOrStdout(), "Next step:\n")
	fmt.Fprintf(cmd.OutOrStdout(), "    gf init-repo <name>\n\n")
	return nil
}

// recoverFromInput handles `gf login --recover`: the user pastes (or pipes)
// the private key directly. The key is verified against the server in
// memory; nothing is written to disk until verification succeeds.
func recoverFromInput(cmd *cobra.Command, serverURL, username, identityPath, cfgPath string) error {
	if _, err := os.Stat(identityPath); err == nil {
		return fmt.Errorf(
			"identity file already exists at %s.\n"+
				"Refusing to overwrite. Remove it first if you want to recover with a new key,\n"+
				"or run 'gf login' without --recover to use the existing identity",
			identityPath)
	}

	raw, err := readPrivateKey(cmd)
	if err != nil {
		return err
	}

	id, err := crypto.ParseIdentity(raw)
	if err != nil {
		return fmt.Errorf("invalid private key: %w (expected base64-encoded 32-byte Ed25519 seed)", err)
	}

	if err := verifyAndStore(cmd, serverURL, username, identityPath, cfgPath, id); err != nil {
		return err
	}

	fmt.Fprintf(cmd.OutOrStdout(), "\nRecovered login as %s on %s.\n", username, serverURL)
	fmt.Fprintf(cmd.OutOrStdout(), "Identity written to %s\n\n", identityPath)
	return nil
}

// recoverFromFile handles the case where the user has already placed their
// identity file at identityPath but has no config yet. Loads the key, then
// shares the verify-and-store path with recoverFromInput.
func recoverFromFile(cmd *cobra.Command, serverURL, username, identityPath, cfgPath string) error {
	slog.Debug("recovery (file) attempt", slog.String("identity_path", identityPath))

	id, err := crypto.LoadIdentity(identityPath)
	if err != nil {
		return fmt.Errorf("loading identity from %s: %w", identityPath, err)
	}

	// Key was already on disk — only the config needs writing. Pass an empty
	// identity path so verifyAndStore skips the SaveIdentity step.
	if err := verifyAndStore(cmd, serverURL, username, "", cfgPath, id); err != nil {
		return err
	}

	fmt.Fprintf(cmd.OutOrStdout(), "\nRecovered login as %s on %s.\n", username, serverURL)
	fmt.Fprintf(cmd.OutOrStdout(), "Using existing identity at %s\n\n", identityPath)
	return nil
}

// verifyAndStore is the shared tail of both recovery paths: prove the
// identity belongs to <username> on <server>, then persist. If identityPath
// is "", the identity is assumed to already be on disk and only the config
// is written.
func verifyAndStore(_ *cobra.Command, serverURL, username, identityPath, cfgPath string, id *crypto.Identity) error {
	// Recovery signs its requests with this key and checks it against what the
	// server has on file; log the fingerprint so a `-v` run shows which key is
	// being presented.
	slog.Debug("verifying identity with server",
		slog.String("fingerprint", id.PublicKeyFingerprint()),
		slog.String("public_key", id.PublicKeyString()))
	client := apiclient.NewAuthenticated(serverURL, username, id.Signer())
	remote, err := client.GetUser(username)
	if err != nil {
		// A server we couldn't reach is not an auth failure — surface the
		// clear connectivity message rather than the misleading "could not
		// verify identity" (which implies the key or username was wrong).
		var unreachable *apiclient.UnreachableError
		if errors.As(err, &unreachable) {
			return err
		}
		// 401 from the server covers both "unknown user" and "wrong key" —
		// the server deliberately doesn't distinguish to avoid leaking
		// username existence. Single message covers both.
		return fmt.Errorf(
			"could not verify identity against %s as %q.\n"+
				"Either the username does not exist on this server, or the\n"+
				"provided private key does not match the registered key.\n\n"+
				"Underlying error: %w",
			serverURL, username, err)
	}
	if remote.PublicKey != id.PublicKeyString() {
		// Server accepted our signature but stored a different pubkey for
		// this username. Shouldn't happen unless the server is buggy — fail
		// loudly rather than write inconsistent state.
		return fmt.Errorf(
			"identity mismatch: local key does not match what %s has on file for %q",
			serverURL, username)
	}

	if identityPath != "" {
		if err := crypto.SaveIdentity(identityPath, id); err != nil {
			return fmt.Errorf("saving identity: %w", err)
		}
	}
	if err := config.Save(cfgPath, &config.Config{Username: username, ServerURL: serverURL}); err != nil {
		// If we wrote the identity but failed to write the config, leave the
		// identity in place — the user can re-run login to recover from it.
		return fmt.Errorf("saving config: %w", err)
	}
	return nil
}

// readPrivateKey reads a base64-encoded Ed25519 seed from stdin. On a TTY
// the input is hidden (like a password prompt) so the key does not appear
// on screen and does not land in scrollback. When stdin is not a terminal
// (piped from another command, or fed by a test), one line is read raw.
func readPrivateKey(cmd *cobra.Command) (string, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		fmt.Fprint(cmd.ErrOrStderr(), "Paste private key (base64-encoded seed): ")
		line, err := term.ReadPassword(fd)
		// ReadPassword swallows the trailing newline the user typed; print
		// our own so subsequent output starts on a fresh line.
		fmt.Fprintln(cmd.ErrOrStderr())
		if err != nil {
			return "", fmt.Errorf("reading private key from terminal: %w", err)
		}
		return string(line), nil
	}

	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil && err != io.EOF {
			return "", fmt.Errorf("reading private key from stdin: %w", err)
		}
		return "", fmt.Errorf("no private key provided on stdin")
	}
	return scanner.Text(), nil
}
