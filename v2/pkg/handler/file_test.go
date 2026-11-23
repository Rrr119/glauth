package handler

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/trace"

	"github.com/glauth/glauth/v2/pkg/config"
)

func newFileTestOptions(t *testing.T, jsonPath string, watch bool) []Option {
	t.Helper()
	log := zerolog.New(os.Stderr)
	return []Option{
		Backend(config.Backend{
			Datastore:          "file",
			BaseDN:             "dc=glauth,dc=com",
			File:               jsonPath,
			WatchFile:          watch,
			NameFormatAsArray:  []string{"cn", "uid"},
			GroupFormatAsArray: []string{"ou", "cn"},
			SSHKeyAttr:         "sshPublicKey",
		}),
		Logger(&log),
		Config(&config.Config{}),
		LDAPHelper(NewLDAPOpsHelper(trace.NewNoopTracerProvider().Tracer("test"))),
		Tracer(trace.NewNoopTracerProvider().Tracer("test")),
	}
}

const sampleFileData = `{
  "groups": [
    {"name": "svc", "gidnumber": 5501},
    {"name": "engineers", "gidnumber": 5502, "includegroups": [5501]},
    {"name": "everyone", "gidnumber": 5503, "includegroups": [5502]}
  ],
  "users": [
    {"name": "alice", "uidnumber": 5001, "primarygroup": 5502, "passsha256": "2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe9d2ea3d6e70"},
    {"name": "bob", "uidnumber": 5002, "primarygroup": 5501}
  ]
}`

func writeFileData(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestFileHandlerLoadsAndFindsUsersAndGroups(t *testing.T) {
	path := filepath.Join(t.TempDir(), "directory.json")
	writeFileData(t, path, sampleFileData)

	h, err := NewFileHandler(newFileTestOptions(t, path, false)...)
	if err != nil {
		t.Fatal(err)
	}

	found, user, err := h.FindUser(context.Background(), "alice", false)
	if err != nil || !found {
		t.Fatalf("FindUser alice: found=%v err=%v", found, err)
	}
	if user.UIDNumber != 5001 || user.PrimaryGroup != 5502 {
		t.Fatalf("unexpected user: %+v", user)
	}

	found, group, err := h.FindGroup(context.Background(), "everyone")
	if err != nil || !found {
		t.Fatalf("FindGroup everyone: found=%v err=%v", found, err)
	}
	if len(group.IncludeGroups) != 1 || group.IncludeGroups[0] != 5502 {
		t.Fatalf("unexpected group: %+v", group)
	}

	// UPN lookups must miss rather than match on name.
	if found, _, _ := h.FindUser(context.Background(), "alice", true); found {
		t.Fatal("UPN lookup should not match a user with no mail")
	}
}

func TestFileHandlerRejectsMissingPathAndBadData(t *testing.T) {
	log := zerolog.New(os.Stderr)
	if _, err := NewFileHandler(
		Backend(config.Backend{Datastore: "file", BaseDN: "dc=glauth,dc=com"}),
		Logger(&log), Config(&config.Config{}),
		LDAPHelper(NewLDAPOpsHelper(trace.NewNoopTracerProvider().Tracer("test"))),
		Tracer(trace.NewNoopTracerProvider().Tracer("test")),
	); err == nil {
		t.Fatal("expected error when no file path is configured")
	}

	dir := t.TempDir()

	missing := filepath.Join(dir, "nope.json")
	if _, err := NewFileHandler(newFileTestOptions(t, missing, false)...); err == nil {
		t.Fatal("expected error for a missing data file")
	}

	badJSON := filepath.Join(dir, "bad.json")
	writeFileData(t, badJSON, "{not json")
	if _, err := NewFileHandler(newFileTestOptions(t, badJSON, false)...); err == nil {
		t.Fatal("expected error for malformed JSON")
	}

	dangling := filepath.Join(dir, "dangling.json")
	writeFileData(t, dangling, `{
	  "groups": [{"name": "g", "gidnumber": 5501, "includegroups": [5599]}],
	  "users": []
	}`)
	if _, err := NewFileHandler(newFileTestOptions(t, dangling, false)...); err == nil {
		t.Fatal("expected error for a dangling include group")
	}

	dupUser := filepath.Join(dir, "dup.json")
	writeFileData(t, dupUser, `{
	  "groups": [{"name": "g", "gidnumber": 5501}],
	  "users": [
	    {"name": "alice", "uidnumber": 5001, "primarygroup": 5501},
	    {"name": "alice", "uidnumber": 5002, "primarygroup": 5501}
	  ]
	}`)
	if _, err := NewFileHandler(newFileTestOptions(t, dupUser, false)...); err == nil {
		t.Fatal("expected error for duplicate user names")
	}
}

func TestFileHandlerHotReloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "directory.json")
	writeFileData(t, path, sampleFileData)

	h, err := NewFileHandler(newFileTestOptions(t, path, true)...)
	if err != nil {
		t.Fatal(err)
	}

	if found, _, _ := h.FindUser(context.Background(), "carol", false); found {
		t.Fatal("carol should not exist before reload")
	}

	updated := `{
	  "groups": [{"name": "svc", "gidnumber": 5501}],
	  "users": [{"name": "carol", "uidnumber": 5003, "primarygroup": 5501}]
	}`
	// Ensure the mtime strictly advances even on filesystems with coarse
	// timestamp granularity.
	time.Sleep(20 * time.Millisecond)
	writeFileData(t, path, updated)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if found, _, _ := h.FindUser(context.Background(), "carol", false); found {
			// The old directory must be gone after a successful swap.
			if found, _, _ := h.FindUser(context.Background(), "alice", false); found {
				t.Fatal("alice should disappear after the directory is replaced")
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("file backend did not hot-reload within the deadline")
}

func TestFileHandlerKeepsDirectoryOnBrokenReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "directory.json")
	writeFileData(t, path, sampleFileData)

	h, err := NewFileHandler(newFileTestOptions(t, path, true)...)
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(20 * time.Millisecond)
	writeFileData(t, path, "{broken")

	// Give the watcher a chance to attempt (and reject) the reload.
	time.Sleep(1500 * time.Millisecond)

	if found, _, _ := h.FindUser(context.Background(), "alice", false); !found {
		t.Fatal("the last good directory must remain served when a reload fails")
	}
}
