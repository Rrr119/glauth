package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/rs/zerolog"

	"github.com/glauth/glauth/v2/internal/monitoring"
	"github.com/glauth/glauth/v2/internal/tracing"
	"github.com/glauth/glauth/v2/pkg/config"
	"github.com/glauth/glauth/v2/pkg/server"
	"github.com/glauth/ldap"
)

// TestConfigBackendInheritanceGuardsBackwardCompatibility proves the
// cycle-safe group expansion refactor keeps the legacy config backend's
// IncludeGroups behaviour intact: parent groups inherit members from their
// children and memberOf lists the transitive parent groups.
func TestConfigBackendInheritanceGuardsBackwardCompatibility(t *testing.T) {
	port := freePort(t)
	pwHash := sha256.Sum256([]byte(testPassword))

	cfg := &config.Config{
		Backends: []config.Backend{{
			Datastore:          "config",
			BaseDN:             testBaseDN,
			NameFormat:         "cn",
			NameFormatAsArray:  []string{"cn"},
			GroupFormat:        "ou",
			GroupFormatAsArray: []string{"ou"},
			SSHKeyAttr:         "sshPublicKey",
		}},
		Groups: []config.Group{
			{Name: "staff", GIDNumber: 5505},
			{Name: "parent", GIDNumber: 5601, IncludeGroups: []int{5602}},
			{Name: "child", GIDNumber: 5602},
		},
		Users: []config.User{
			{
				Name: "serviceuser", UIDNumber: 4000, PrimaryGroup: 5505,
				PassSHA256:   hex.EncodeToString(pwHash[:]),
				Capabilities: []config.Capability{{Action: "search", Object: "*"}},
			},
			{Name: "alice", UIDNumber: 5001, PrimaryGroup: 5602, PassSHA256: hex.EncodeToString(pwHash[:])},
		},
		LDAP:  config.LDAP{Enabled: true, Listen: fmt.Sprintf("127.0.0.1:%d", port), TLS: false},
		LDAPS: config.LDAPS{Enabled: false},
	}

	log := zerolog.New(nil)
	svc, err := server.NewServer(
		server.Logger(log),
		server.Config(cfg),
		server.Monitor(monitoring.NewMonitor(&log)),
		server.Tracer(tracing.NewTracer(tracing.NewConfig(false, "", "", &log))),
	)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = svc.ListenAndServe() }()
	waitForLDAP(t, fmt.Sprintf("127.0.0.1:%d", port))
	defer svc.Shutdown()

	conn, err := ldap.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.Bind("cn=serviceuser,ou=staff,ou=users,"+testBaseDN, testPassword); err != nil {
		t.Fatal(err)
	}

	// The parent group returns the child's member through inheritance.
	parentMembers, err := conn.Search(ldap.NewSearchRequest(
		testBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(memberOf=ou=parent,ou=groups,"+testBaseDN+")", []string{"cn"}, nil,
	))
	if err != nil {
		t.Fatal(err)
	}
	if len(parentMembers.Entries) != 1 || parentMembers.Entries[0].DN != "cn=alice,ou=child,ou=users,"+testBaseDN {
		t.Fatalf("parent inherited members = %v", parentMembers.Entries)
	}

	// alice's memberOf carries both her direct group and the inheriting parent.
	alice, err := conn.Search(ldap.NewSearchRequest(
		testBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(cn=alice)", []string{"memberOf"}, nil,
	))
	if err != nil {
		t.Fatal(err)
	}
	if len(alice.Entries) != 1 {
		t.Fatalf("alice lookup = %d entries", len(alice.Entries))
	}
	memberOf := alice.Entries[0].GetAttributeValues("memberOf")
	want := map[string]bool{
		"ou=child,ou=groups," + testBaseDN:  false,
		"ou=parent,ou=groups," + testBaseDN: false,
	}
	if len(memberOf) != len(want) {
		t.Fatalf("memberOf = %v", memberOf)
	}
	for _, dn := range memberOf {
		if _, ok := want[dn]; !ok {
			t.Fatalf("unexpected memberOf %q in %v", dn, memberOf)
		}
	}
}
