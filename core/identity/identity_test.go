package identity

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestIdentityIsStableFromPrivateKey(t *testing.T) {
	private := bytes.Repeat([]byte{7}, KeySize)
	first, err := FromPrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	second, err := FromPrivateKey(first.PrivateKey())
	if err != nil {
		t.Fatal(err)
	}
	if first.ID() != second.ID() {
		t.Fatalf("identity changed: %s != %s", first.ID(), second.ID())
	}
	if _, err := ParseID(first.ID().String()); err != nil {
		t.Fatal(err)
	}
}

func TestFileStoreLoadOrCreate(t *testing.T) {
	directory := t.TempDir()
	store := FileStore{Directory: directory}
	first, err := store.LoadOrCreate("node")
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.LoadOrCreate("node")
	if err != nil {
		t.Fatal(err)
	}
	if first.ID() != second.ID() {
		t.Fatal("stored identity was not persistent")
	}
	info, err := os.Stat(filepath.Join(directory, "node.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("identity mode = %o, want 600", info.Mode().Perm())
	}
}

func TestFileStoreRejectsPathTraversal(t *testing.T) {
	store := FileStore{Directory: t.TempDir()}
	identity, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save("../escaped", identity); err == nil {
		t.Fatal("store accepted path traversal")
	}
}
