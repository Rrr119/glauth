package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"

	"github.com/glauth/glauth/v2/pkg/config"
	"github.com/glauth/ldap"
)

// fileData is the on-disk representation of a file backend. It mirrors the
// users and groups sections of the TOML configuration so the same identity
// model, including group inheritance through IncludeGroups, is available to
// a directory that can be rewritten out of band.
type fileData struct {
	Users  []config.User  `json:"users"`
	Groups []config.Group `json:"groups"`
}

// fileHandler serves identities stored in a JSON file. The LDAP semantics are
// delegated to configHandler: this type only owns loading, reloading and
// swapping the in-memory directory the embedded handler reads from.
type fileHandler struct {
	configHandler

	path       string
	log        *zerolog.Logger
	current    atomic.Pointer[config.Config]
	stopReload chan struct{}
}

// NewFileHandler creates a backend backed by a JSON directory file.
func NewFileHandler(opts ...Option) (Handler, error) {
	options := newOptions(opts...)

	if options.Backend.File == "" {
		return nil, fmt.Errorf("file backend requires a 'file' setting pointing at the JSON data file")
	}

	// The embedded configHandler reads Users and Groups from a dedicated
	// config instance, never from the global TOML config, so a file backend
	// keeps working when chained after other backends that share the process.
	// Each reload publishes a fresh, immutable pointer so in-flight requests
	// never observe a half-swapped directory.
	dataCfg := &config.Config{
		Behaviors: options.Config.Behaviors,
	}

	h := &fileHandler{
		path:       options.Backend.File,
		log:        options.Logger,
		stopReload: make(chan struct{}),
	}
	h.current.Store(dataCfg)

	if err := h.load(); err != nil {
		return nil, err
	}

	// Build the configHandler against the file-backed config so every LDAP
	// operation (bind, search, group expansion) is reused unchanged.
	h.configHandler = NewConfigHandler(
		Backend(options.Backend),
		Logger(options.Logger),
		Config(h.current.Load()),
		YubiAuth(options.YubiAuth),
		LDAPHelper(options.LDAPHelper),
		Monitor(options.Monitor),
		Tracer(options.Tracer),
	).(configHandler)

	if options.Backend.WatchFile {
		go h.watch()
	}

	return h, nil
}

// load reads and validates the JSON file and publishes a new immutable config
// snapshot. A broken file never replaces the directory currently being served.
func (h *fileHandler) load() error {
	raw, err := os.ReadFile(h.path)
	if err != nil {
		return fmt.Errorf("unable to read file backend data %q: %w", h.path, err)
	}

	var data fileData
	if err := json.Unmarshal(raw, &data); err != nil {
		return fmt.Errorf("unable to parse file backend data %q: %w", h.path, err)
	}

	if err := validateFileData(data); err != nil {
		return fmt.Errorf("invalid file backend data %q: %w", h.path, err)
	}

	next := *h.current.Load() // copy the shared settings (e.g. Behaviors)
	next.Users = data.Users
	next.Groups = data.Groups
	next.FileLoadedAt = time.Now()
	h.current.Store(&next)

	h.log.Info().Str("file", h.path).Int("users", len(data.Users)).Int("groups", len(data.Groups)).Msg("File backend loaded")
	return nil
}

// validateFileData fails fast on references that would make group resolution
// ambiguous: duplicate names, duplicate ids and dangling group inheritance.
func validateFileData(data fileData) error {
	userNames := make(map[string]bool, len(data.Users))
	userIDs := make(map[int]bool, len(data.Users))
	for _, user := range data.Users {
		if user.Name == "" {
			return fmt.Errorf("a user has no name")
		}
		if userNames[user.Name] {
			return fmt.Errorf("duplicate user name %q", user.Name)
		}
		userNames[user.Name] = true
		if user.UIDNumber != 0 {
			if userIDs[user.UIDNumber] {
				return fmt.Errorf("duplicate uidNumber %d on user %q", user.UIDNumber, user.Name)
			}
			userIDs[user.UIDNumber] = true
		}
	}

	groupNames := make(map[string]bool, len(data.Groups))
	groupIDs := make(map[int]bool, len(data.Groups))
	for _, group := range data.Groups {
		if group.Name == "" {
			return fmt.Errorf("a group has no name")
		}
		if groupNames[group.Name] {
			return fmt.Errorf("duplicate group name %q", group.Name)
		}
		groupNames[group.Name] = true
		if groupIDs[group.GIDNumber] {
			return fmt.Errorf("duplicate gidNumber %d on group %q", group.GIDNumber, group.Name)
		}
		groupIDs[group.GIDNumber] = true
	}

	for _, group := range data.Groups {
		for _, included := range group.IncludeGroups {
			if included == group.GIDNumber {
				return fmt.Errorf("group %q includes itself", group.Name)
			}
			if !groupIDs[included] {
				return fmt.Errorf("group %q includes unknown group id %d", group.Name, included)
			}
		}
	}
	return nil
}

// watch polls the file's modification time and reloads atomically when it
// changes. Polling (rather than fsnotify) keeps the backend self-contained and
// survives editors that replace the file with a rename.
func (h *fileHandler) watch() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-h.stopReload:
			return
		case <-ticker.C:
			info, err := os.Stat(h.path)
			if err != nil {
				h.log.Warn().Err(err).Str("file", h.path).Msg("File backend data not accessible; keeping current directory")
				continue
			}
			current := h.current.Load()
			if !info.ModTime().After(current.FileLoadedAt) {
				continue
			}
			if err := h.load(); err != nil {
				h.log.Warn().Err(err).Msg("File backend reload failed; keeping current directory")
			} else {
				h.log.Info().Str("file", h.path).Msg("File backend reloaded")
			}
		}
	}
}

// Close stops the reload goroutine, if any, and closes the embedded handler.
func (h *fileHandler) Close(boundDN string, conn net.Conn) error {
	select {
	case <-h.stopReload:
	default:
		close(h.stopReload)
	}
	return h.configHandler.Close(boundDN, conn)
}

// snapshot returns the directory config currently being served. The returned
// pointer must be treated as read-only.
func (h *fileHandler) snapshot() *config.Config {
	return h.current.Load()
}

// active builds a configHandler bound to the latest snapshot. The handler is
// a tiny value type, so constructing it per request is cheap and guarantees
// every LDAP operation observes the most recently published directory.
func (h *fileHandler) active() configHandler {
	ch := h.configHandler
	ch.cfg = h.snapshot()
	return ch
}

// Bind, Search and the directory lookups are redeclared so they always run
// against the latest snapshot rather than the config pointer captured when the
// backend was constructed.

func (h *fileHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (ldap.LDAPResultCode, error) {
	return h.active().Bind(bindDN, bindSimplePw, conn)
}

func (h *fileHandler) Search(bindDN string, searchReq ldap.SearchRequest, conn net.Conn) (ldap.ServerSearchResult, error) {
	return h.active().Search(bindDN, searchReq, conn)
}

func (h *fileHandler) FindUser(ctx context.Context, userName string, searchByUPN bool) (bool, config.User, error) {
	return h.active().FindUser(ctx, userName, searchByUPN)
}

func (h *fileHandler) FindGroup(ctx context.Context, groupName string) (bool, config.Group, error) {
	return h.active().FindGroup(ctx, groupName)
}

func (h *fileHandler) FindPosixAccounts(ctx context.Context, hierarchy string) ([]*ldap.Entry, error) {
	return h.active().FindPosixAccounts(ctx, hierarchy)
}

func (h *fileHandler) FindPosixGroups(ctx context.Context, hierarchy string) ([]*ldap.Entry, error) {
	return h.active().FindPosixGroups(ctx, hierarchy)
}

// GetCfg returns the live snapshot so the shared LDAPOpsHelper always sees the
// current directory during Bind and Search.
func (h *fileHandler) GetCfg() *config.Config {
	return h.snapshot()
}

// Compile-time guard that fileHandler satisfies the full Handler contract.
var _ Handler = (*fileHandler)(nil)
