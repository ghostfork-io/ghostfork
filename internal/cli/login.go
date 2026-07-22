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
	Long: `Log in to a Ghostfork account, or recover one on a new machine.

Accounts are created by registering on the web, not by this command. gf
login authenticates against an existing account and sets up this machine's
identity.

What happens depends on what's on disk and which flags are set:

  1. No identity yet → log in with your account password.
     gf prompts for the password (use --password to pass or pipe it
     instead). If the account has no key yet (first login), a fresh
     Ed25519 keypair is generated locally and its public key is uploaded.
     If the account already has a key, gf refuses and tells you to recover
     with --recover instead. An unknown account fails the password check —
     accounts are created by registering on the web, not here.

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
	Example: `  # First login after registering on the web (prompts for the password)
  gf login --server https://api.example.com --username alice

  # Pass the password non-interactively (e.g. scripted; visible in process list)
  gf login --server https://api.example.com --username alice --password "$PW"

  # Recover on a new machine via terminal paste (key is hidden as you type)
  gf login --server https://api.example.com --username alice --recover

  # Recover non-interactively (e.g. from a CI secret)
  echo "$BACKED_UP_KEY" | gf login --server https://api.example.com --username alice --recover`,
	RunE: runLogin,
}

func init() {
	loginCmd.Flags().String("server", "", "server URL (required)")
	loginCmd.Flags().String("username", "", "username to log in as (required)")
	loginCmd.Flags().Bool("recover", false, "recover an existing account by providing the private key on stdin (hidden prompt on a TTY)")
	loginCmd.Flags().String("password", "", "account password; if omitted, gf prompts for it (hidden). First login bootstraps a keypair")
	loginCmd.MarkFlagRequired("server")
	loginCmd.MarkFlagRequired("username")
}

func runLogin(cmd *cobra.Command, _ []string) error {
	serverURL, _ := cmd.Flags().GetString("server")
	username, _ := cmd.Flags().GetString("username")
	doRecover, _ := cmd.Flags().GetBool("recover")
	password, _ := cmd.Flags().GetString("password")
	passwordGiven := cmd.Flags().Changed("password")

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
		slog.Bool("password", passwordGiven), // presence only — never the value
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

	// No identity on disk: authenticate with the account password to bootstrap a
	// key on first login (or learn the account already has one and must be
	// recovered). The password is prompted for when not supplied on the command
	// line, so a bare `gf login --username <name>` is enough. Accounts are
	// created by web registration, not here — an unknown account fails the
	// password check rather than being silently created.
	return bootstrapLogin(cmd, serverURL, username, password, identityPath, cfgPath)
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

// bootstrapLogin handles `gf login --password ...` for an account created on
// the web. It authenticates with the password, then either generates a fresh
// keypair and uploads its public key (first login on this account), or — if the
// account already has a key — refuses and points the user at key recovery.
//
// It is only reached when no identity file exists locally, so it never
// overwrites a working key.
func bootstrapLogin(cmd *cobra.Command, serverURL, username, password, identityPath, cfgPath string) error {
	// An explicit empty --password means "prompt me" (so the password never
	// lands in shell history or the process list).
	if password == "" {
		var err error
		password, err = readPassword(cmd)
		if err != nil {
			return err
		}
		if password == "" {
			return fmt.Errorf("no password provided")
		}
	}

	client := apiclient.New(serverURL)
	slog.Debug("authenticating with password", slog.String("username", username))
	resp, err := client.Login(username, password)
	if err != nil {
		var unreachable *apiclient.UnreachableError
		if errors.As(err, &unreachable) {
			return err
		}
		return fmt.Errorf(
			"login failed for %q on %s — check the username and password.\n\n"+
				"Underlying error: %w", username, serverURL, err)
	}

	// Account already has a key: this machine must restore the original private
	// key rather than mint a new one (the server can't — it never had it).
	if resp.HasPublicKey {
		return fmt.Errorf(
			"account %q already has a registered public key.\n"+
				"To use it on this machine, restore your backed-up private key:\n\n"+
				"    gf login --server %s --username %s --recover\n\n"+
				"(paste the private key when prompted), or copy your identity file to\n"+
				"%s and re-run 'gf login'. V1 has no key recovery if the key is lost.",
			username, serverURL, username, identityPath)
	}

	// First login: generate the keypair locally and upload the public key.
	slog.Debug("generating new identity")
	id, err := crypto.GenerateIdentity()
	if err != nil {
		return fmt.Errorf("generating identity: %w", err)
	}
	slog.Debug("uploading public key to server",
		slog.String("fingerprint", id.PublicKeyFingerprint()),
		slog.String("public_key", id.PublicKeyString()))
	if err := client.UploadPublicKey(username, password, id.PublicKeyString()); err != nil {
		var unreachable *apiclient.UnreachableError
		if errors.As(err, &unreachable) {
			return err
		}
		return fmt.Errorf("uploading public key: %w", err)
	}
	slog.Debug("public key bootstrap complete")

	if err := crypto.SaveIdentity(identityPath, id); err != nil {
		return fmt.Errorf("saving identity: %w", err)
	}
	if err := config.Save(cfgPath, &config.Config{Username: username, ServerURL: serverURL}); err != nil {
		return fmt.Errorf("saving config: %w", err)
	}
	slog.Debug("identity and config written",
		slog.String("identity_path", identityPath),
		slog.String("config_path", cfgPath),
	)

	fmt.Fprintf(cmd.OutOrStdout(), "\nLogged in as %s on %s.\n", username, serverURL)
	fmt.Fprintf(cmd.OutOrStdout(), "A new keypair was generated and its public key registered.\n")
	fmt.Fprintf(cmd.OutOrStdout(), "Identity written to %s\n", identityPath)
	fmt.Fprintf(cmd.OutOrStdout(), "Back this file up — V1 has no key recovery if it is lost.\n\n")
	fmt.Fprintf(cmd.OutOrStdout(), "You're ready to create your first GF vault.\n\n")
	fmt.Fprintf(cmd.OutOrStdout(), "    gf init-vault <name>\n\n")
	fmt.Fprintf(cmd.OutOrStdout(), "A vault is the encrypted container on Ghostfork that you push a git repo\n")
	fmt.Fprintf(cmd.OutOrStdout(), "into. <name> is the label you want to give it (e.g. \"myproject\") — it's\n")
	fmt.Fprintf(cmd.OutOrStdout(), "arbitrary and does NOT need to match your git repo's name. This registers\n")
	fmt.Fprintf(cmd.OutOrStdout(), "a new vault on the server and sets up local encryption for it.\n\n")
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

// readPassword reads an account password. On a TTY the input is hidden (like a
// password prompt) so it does not appear on screen or in scrollback; when stdin
// is piped, one line is read raw. Used by 'gf login --password' when the flag
// is given with no value.
func readPassword(cmd *cobra.Command) (string, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		fmt.Fprint(cmd.ErrOrStderr(), "Password: ")
		line, err := term.ReadPassword(fd)
		fmt.Fprintln(cmd.ErrOrStderr())
		if err != nil {
			return "", fmt.Errorf("reading password from terminal: %w", err)
		}
		return string(line), nil
	}

	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil && err != io.EOF {
			return "", fmt.Errorf("reading password from stdin: %w", err)
		}
		return "", fmt.Errorf("no password provided on stdin")
	}
	return scanner.Text(), nil
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
