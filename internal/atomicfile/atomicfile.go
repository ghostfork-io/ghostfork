// Package atomicfile writes files atomically: encode to a sibling temp file,
// then rename into place. A crash or encode error never leaves the target
// path in a partial or corrupt state.
package atomicfile

import (
	"io"
	"os"
	"path/filepath"
)

// Write atomically writes to path. It creates path's parent directory with
// mode 0700 if needed, opens a sibling temp file with mode, calls encode to
// produce its contents, and renames the temp file over path on success.
//
// If encode or any I/O step fails, the temp file is removed and the existing
// file at path (if any) is left untouched.
func Write(path string, mode os.FileMode, encode func(io.Writer) error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}

	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}

	if err := encode(f); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
