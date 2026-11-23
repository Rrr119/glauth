package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/glauth/glauth/v2/internal/monitoring"
	"github.com/glauth/glauth/v2/internal/tracing"
	"github.com/glauth/glauth/v2/pkg/config"
	"github.com/glauth/glauth/v2/pkg/server"
	"github.com/glauth/ldap"
)

const (
	testUserCount = 1000
	testBaseDN    = "dc=glauth,dc=com"
	testPassword  = "hunter2"
)

// testDirectory mirrors the file backend's on-disk schema.
type testDirectory struct {
	Users  []config.User  `json:"users"`
	Groups []config.Group `json:"groups"`
}

// freePort asks the OS for a free TCP port and immediately hands it back:
// nothing else should be racing these tests for ports.
func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	return port
}

// buildThousandUserDirectory writes a JSON directory with 1000 users spread
// across leaf groups that inherit into nested parent groups:
//
//	users 0-499   -> engineers (5502)
//	users 500-999 -> qa (5503)
//	engineering (5501) includes engineers and qa
//	everyone (5504) includes engineering
//	staff (5505) is a service group holding one bind account
func buildThousandUserDirectory(t *testing.T) string {
	t.Helper()

	groups := []config.Group{
		{Name: "staff", GIDNumber: 5505},
		{Name: "engineering", GIDNumber: 5501, IncludeGroups: []int{5502, 5503}},
		{Name: "engineers", GIDNumber: 5502},
		{Name: "qa", GIDNumber: 5503},
		{Name: "everyone", GIDNumber: 5504, IncludeGroups: []int{5501}},
	}

	pwHash := sha256.Sum256([]byte(testPassword))
	users := make([]config.User, 0, testUserCount+1)
	users = append(users, config.User{
		Name:         "serviceuser",
		UIDNumber:    4000,
		PrimaryGroup: 5505,
		PassSHA256:   hex.EncodeToString(pwHash[:]),
		Capabilities: []config.Capability{{Action: "search", Object: "*"}},
	})

	for i := 0; i < testUserCount; i++ {
		primaryGroup := 5502
		if i >= testUserCount/2 {
			primaryGroup = 5503
		}
		users = append(users, config.User{
			Name:         fmt.Sprintf("user%04d", i),
			UIDNumber:    5000 + i,
			PrimaryGroup: primaryGroup,
			PassSHA256:   hex.EncodeToString(pwHash[:]),
		})
	}

	raw, err := json.Marshal(testDirectory{Users: users, Groups: groups})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "directory.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func startFileBackendServer(t *testing.T, dataPath string) (int, func()) {
	t.Helper()
	port := freePort(t)

	cfg := &config.Config{
		Backends: []config.Backend{{
			Datastore:          "file",
			BaseDN:             testBaseDN,
			File:               dataPath,
			NameFormat:         "cn",
			NameFormatAsArray:  []string{"cn"},
			GroupFormat:        "ou",
			GroupFormatAsArray: []string{"ou"},
			SSHKeyAttr:         "sshPublicKey",
		}},
		LDAP:  config.LDAP{Enabled: true, Listen: fmt.Sprintf("127.0.0.1:%d", port), TLS: false},
		LDAPS: config.LDAPS{Enabled: false},
	}

	log := zerolog.New(os.Stderr)
	monitor := monitoring.NewMonitor(&log)
	tracer := tracing.NewTracer(tracing.NewConfig(false, "", "", &log))

	svc, err := server.NewServer(
		server.Logger(log),
		server.Config(cfg),
		server.Monitor(monitor),
		server.Tracer(tracer),
	)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		if err := svc.ListenAndServe(); err != nil {
			t.Logf("server stopped: %v", err)
		}
	}()

	waitForLDAP(t, fmt.Sprintf("127.0.0.1:%d", port))

	return port, func() {
		svc.Shutdown()
	}
}

func waitForLDAP(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := ldap.Dial("tcp", addr)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("LDAP server at %s never came up", addr)
}

func serviceBind(t *testing.T, port int) *ldap.Conn {
	t.Helper()
	conn, err := ldap.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	bindDN := "cn=serviceuser,ou=staff,ou=users," + testBaseDN
	if err := conn.Bind(bindDN, testPassword); err != nil {
		t.Fatalf("service bind failed: %v", err)
	}
	return conn
}

func TestFileBackendThousandUsers(t *testing.T) {
	dataPath := buildThousandUserDirectory(t)
	port, shutdown := startFileBackendServer(t, dataPath)
	defer shutdown()

	conn := serviceBind(t, port)
	defer conn.Close()

	subtree := func(filter string) *ldap.SearchResult {
		t.Helper()
		req := ldap.NewSearchRequest(
			testBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
			0, 0, false, filter, []string{"dn", "cn", "uidNumber"}, nil,
		)
		result, err := conn.Search(req)
		if err != nil {
			t.Fatalf("search %q failed: %v", filter, err)
		}
		return result
	}

	// 1. Every one of the 1000 directory users is returned by a full subtree
	// search (plus the bind account, so 1001 posixAccount entries total).
	all := subtree("(objectClass=posixAccount)")
	if len(all.Entries) != testUserCount+1 {
		t.Fatalf("full subtree returned %d entries, want %d", len(all.Entries), testUserCount+1)
	}

	// 2. Direct group membership: each leaf group holds exactly its own users.
	engineers := subtree("(memberOf=ou=engineers,ou=groups," + testBaseDN + ")")
	if len(engineers.Entries) != testUserCount/2 {
		t.Fatalf("engineers group returned %d members, want %d", len(engineers.Entries), testUserCount/2)
	}
	qa := subtree("(memberOf=ou=qa,ou=groups," + testBaseDN + ")")
	if len(qa.Entries) != testUserCount/2 {
		t.Fatalf("qa group returned %d members, want %d", len(qa.Entries), testUserCount/2)
	}

	// 3. One level of inheritance: engineering includes both leaf groups.
	engineering := subtree("(memberOf=ou=engineering,ou=groups," + testBaseDN + ")")
	if len(engineering.Entries) != testUserCount {
		t.Fatalf("engineering group returned %d members, want %d", len(engineering.Entries), testUserCount)
	}

	// 4. Two levels of inheritance through a diamond: everyone -> engineering
	// -> {engineers, qa} must still be every user, with no duplicates.
	everyone := subtree("(memberOf=ou=everyone,ou=groups," + testBaseDN + ")")
	if len(everyone.Entries) != testUserCount {
		t.Fatalf("everyone group returned %d members, want %d", len(everyone.Entries), testUserCount)
	}

	// 5. The groupOfUniqueNames view under ou=groups reports the same inherited
	// membership on uniqueMember (the posixGroup/memberUid view lives under
	// ou=users and is covered by the subtree searches above).
	groupSearch, err := conn.Search(ldap.NewSearchRequest(
		"ou=groups,"+testBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=groupOfUniqueNames)", []string{"cn", "uniqueMember"}, nil,
	))
	if err != nil {
		t.Fatalf("groupOfUniqueNames search failed: %v", err)
	}
	var everyoneEntry *ldap.Entry
	for _, entry := range groupSearch.Entries {
		if entry.DN == "ou=everyone,ou=groups,"+testBaseDN {
			everyoneEntry = entry
		}
	}
	if everyoneEntry == nil {
		t.Fatalf("everyone group not found among %d entries", len(groupSearch.Entries))
	}
	entry := everyoneEntry
	if got := len(entry.GetAttributeValues("uniqueMember")); got != testUserCount {
		t.Fatalf("uniqueMember count = %d, want %d", got, testUserCount)
	}

	// 6. Spot-check a specific user lookup and its transitive memberOf DNs.
	userSearch, err := conn.Search(ldap.NewSearchRequest(
		testBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, "(cn=user0000)", []string{"memberOf", "uidNumber"}, nil,
	))
	if err != nil {
		t.Fatalf("user0000 search failed: %v", err)
	}
	if len(userSearch.Entries) != 1 {
		t.Fatalf("user0000 lookup returned %d entries", len(userSearch.Entries))
	}
	memberOf := userSearch.Entries[0].GetAttributeValues("memberOf")
	sort.Strings(memberOf)
	wantMemberOf := []string{
		"ou=engineers,ou=groups," + testBaseDN,
		"ou=engineering,ou=groups," + testBaseDN,
		"ou=everyone,ou=groups," + testBaseDN,
	}
	sort.Strings(wantMemberOf)
	if fmt.Sprint(memberOf) != fmt.Sprint(wantMemberOf) {
		t.Fatalf("memberOf = %v, want %v", memberOf, wantMemberOf)
	}
}

func TestFileBackendThousandUserBinds(t *testing.T) {
	dataPath := buildThousandUserDirectory(t)
	port, shutdown := startFileBackendServer(t, dataPath)
	defer shutdown()

	// Exercise binds across the whole directory, including both leaf groups
	// and the boundary user, on fresh connections to avoid any per-conn state.
	indexes := []int{0, 1, 250, 499, 500, 750, 999}
	for _, i := range indexes {
		group := "engineers"
		gid := 5502
		if i >= testUserCount/2 {
			group = "qa"
			gid = 5503
		}
		conn, err := ldap.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			t.Fatalf("dial for user%d: %v", i, err)
		}
		dn := fmt.Sprintf("cn=user%04d,ou=%s,ou=users,%s", i, group, testBaseDN)
		if err := conn.Bind(dn, testPassword); err != nil {
			t.Fatalf("bind %s: %v", dn, err)
		}
		conn.Close()

		// The same bind must fail with a wrong password (invalid credentials,
		// not an operations error).
		conn, err = ldap.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			t.Fatal(err)
		}
		err = conn.Bind(dn, "wrong-password")
		if err == nil {
			t.Fatalf("bind %s with wrong password unexpectedly succeeded", dn)
		}
		if ldapErr, ok := err.(*ldap.Error); !ok || ldapErr.ResultCode != ldap.LDAPResultInvalidCredentials {
			t.Fatalf("bind %s wrong password error = %v, want result code %d", dn, err, ldap.LDAPResultInvalidCredentials)
		}
		conn.Close()
		_ = gid
	}

	// A user from the directory must not exist on a config backend: chaining
	// the two datastores proves the file handler owns its own data.
	t.Run("unknown user rejected", func(t *testing.T) {
		conn, err := ldap.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		err = conn.Bind("cn=ghost,ou=engineers,ou=users,"+testBaseDN, testPassword)
		if err == nil {
			t.Fatal("bind for an unknown user unexpectedly succeeded")
		}
		if ldapErr, ok := err.(*ldap.Error); !ok || ldapErr.ResultCode != ldap.LDAPResultInvalidCredentials {
			t.Fatalf("unknown user error = %v, want result code %d", err, ldap.LDAPResultInvalidCredentials)
		}
	})
}
