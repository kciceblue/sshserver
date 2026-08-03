// Package instance manages crash-resumable, idempotent initialization of one
// user-owned sync-server instance.
package instance

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"

	"github.com/kciceblue/sshserver/runtime/internal/config"
	"github.com/kciceblue/sshserver/runtime/internal/store"
)

type Instance struct {
	Paths    config.Paths
	Settings config.Settings
	Store    *store.Store
	lock     *fileLock
}

// InitializationLease serializes validation and initialization of one state
// directory. Deployment apply acquires it before its final instance preflight
// and hands the same lease into Initialize, closing the race between validation
// and the journaled initialization step.
type InitializationLease struct {
	stateDir string
	lock     *fileLock
}

// InitializationLockCreated reports whether this exact lease atomically
// created the persistent lock path rather than opening a previously disclosed
// lock. Deployment confirmation uses it to enforce the previewed action plan.
func (lease *InitializationLease) InitializationLockCreated() bool {
	return lease != nil && lease.lock != nil && lease.lock.created
}

func AcquireInitializationLease(stateDir string) (*InitializationLease, error) {
	paths := config.ForStateDir(stateDir)
	if err := config.EnsureStateDirectory(paths.StateDir); err != nil {
		return nil, err
	}
	lock, err := acquireLock(paths.StateDir)
	if err != nil {
		return nil, err
	}
	return &InitializationLease{stateDir: paths.StateDir, lock: lock}, nil
}

func (lease *InitializationLease) Initialize(ctx context.Context, requestedListeners []string) (config.Settings, error) {
	if lease == nil || lease.lock == nil {
		return config.Settings{}, errors.New("initialization lease is closed")
	}
	return initializeWithLease(ctx, lease.stateDir, requestedListeners)
}

func (lease *InitializationLease) Close() error {
	if lease == nil || lease.lock == nil {
		return nil
	}
	err := lease.lock.Close()
	lease.lock = nil
	return err
}

func Initialize(ctx context.Context, stateDir string, requestedListeners []string) (returnSettings config.Settings, returnErr error) {
	lease, err := AcquireInitializationLease(stateDir)
	if err != nil {
		return config.Settings{}, err
	}
	defer func() {
		if closeErr := lease.Close(); closeErr != nil {
			returnErr = errors.Join(
				returnErr,
				fmt.Errorf("release initialization lock: %w", closeErr),
			)
		}
	}()
	return lease.Initialize(ctx, requestedListeners)
}

func initializeWithLease(ctx context.Context, stateDir string, requestedListeners []string) (returnSettings config.Settings, returnErr error) {
	paths := config.ForStateDir(stateDir)
	marker, markerErr := config.LoadMarker(paths.InstallMarker)
	markerExists := markerErr == nil
	if markerErr != nil && !errors.Is(markerErr, os.ErrNotExist) {
		return config.Settings{}, fmt.Errorf("load install marker: %w", markerErr)
	}
	if markerExists && marker.Phase == "ready" {
		opened, err := Open(ctx, stateDir)
		if err != nil {
			return config.Settings{}, fmt.Errorf("validate completed installation: %w", err)
		}
		defer func() {
			if closeErr := opened.Close(); closeErr != nil {
				returnErr = errors.Join(
					returnErr,
					fmt.Errorf("close validated installation: %w", closeErr),
				)
			}
		}()
		if requestedListeners != nil && !config.SameListeners(requestedListeners, opened.Settings.Listeners) {
			return config.Settings{}, errors.New("refusing to change listeners during idempotent initialization")
		}
		return opened.Settings, nil
	}

	if err := config.SaveMarker(paths.InstallMarker, config.InstallMarker{
		Generation: "1",
		Phase:      "initializing",
		State:      "resume",
	}); err != nil {
		return config.Settings{}, fmt.Errorf("record installation start: %w", err)
	}

	settings, err := config.LoadSettings(paths.Config)
	if err != nil {
		if !errors.Is(err, config.ErrUninitialized) {
			return config.Settings{}, err
		}
		if exists(paths.InstanceSecret) || exists(paths.Database) {
			return config.Settings{}, errors.New("partial installation has secret or database but no recoverable config")
		}
		listeners := requestedListeners
		if listeners == nil {
			listeners = config.DefaultListeners()
		}
		settings, err = config.NewSettings(listeners)
		if err != nil {
			return config.Settings{}, err
		}
		if err := config.SaveSettings(paths.Config, settings); err != nil {
			return config.Settings{}, fmt.Errorf("write config: %w", err)
		}
	} else if requestedListeners != nil && !config.SameListeners(requestedListeners, settings.Listeners) {
		return config.Settings{}, errors.New("refusing to replace existing listener configuration")
	}

	secret, err := config.ReadSecret(paths.InstanceSecret)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return config.Settings{}, fmt.Errorf("read instance secret: %w", err)
		}
		secret = make([]byte, 32)
		defer func() {
			for index := range secret {
				secret[index] = 0
			}
		}()
		if _, err := rand.Read(secret); err != nil {
			return config.Settings{}, fmt.Errorf("generate instance secret: %w", err)
		}
		if err := config.WriteSecret(paths.InstanceSecret, secret); err != nil {
			return config.Settings{}, fmt.Errorf("write instance secret: %w", err)
		}
	} else {
		for index := range secret {
			secret[index] = 0
		}
	}

	database, err := store.Open(ctx, paths.Database, store.Identity{
		InstanceID: settings.InstanceID,
		VaultID:    settings.VaultID,
	})
	if err != nil {
		return config.Settings{}, err
	}
	if err := database.Close(); err != nil {
		return config.Settings{}, fmt.Errorf("close initialized database: %w", err)
	}
	if err := config.SaveMarker(paths.InstallMarker, config.InstallMarker{
		Generation: "1",
		Phase:      "ready",
		State:      "complete",
	}); err != nil {
		return config.Settings{}, fmt.Errorf("record installation completion: %w", err)
	}
	return settings, nil
}

func Open(ctx context.Context, stateDir string) (*Instance, error) {
	paths := config.ForStateDir(stateDir)
	if err := config.EnsureStateDirectory(paths.StateDir); err != nil {
		return nil, err
	}
	marker, err := config.LoadMarker(paths.InstallMarker)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, config.ErrUninitialized
		}
		return nil, fmt.Errorf("load install marker: %w", err)
	}
	if marker.Phase != "ready" || marker.State != "complete" {
		return nil, errors.New("installation is incomplete; rerun init")
	}
	settings, err := config.LoadSettings(paths.Config)
	if err != nil {
		return nil, err
	}
	secret, err := config.ReadSecret(paths.InstanceSecret)
	if err != nil {
		return nil, fmt.Errorf("validate instance secret: %w", err)
	}
	for index := range secret {
		secret[index] = 0
	}
	database, err := store.Open(ctx, paths.Database, store.Identity{
		InstanceID: settings.InstanceID,
		VaultID:    settings.VaultID,
	})
	if err != nil {
		return nil, err
	}
	return &Instance{Paths: paths, Settings: settings, Store: database}, nil
}

// LoadCompletedSettings reads only the protected completion marker and config
// for an initialized instance. It deliberately avoids EnsureStateDirectory,
// the instance secret, and SQLite so endpoint discovery cannot create, repair,
// or otherwise mutate server state.
func LoadCompletedSettings(stateDir string) (config.Settings, error) {
	if err := config.ValidateStateDirectory(stateDir); err != nil {
		return config.Settings{}, err
	}
	paths := config.ForStateDir(stateDir)
	marker, err := config.LoadMarker(paths.InstallMarker)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return config.Settings{}, config.ErrUninitialized
		}
		return config.Settings{}, fmt.Errorf("load install marker: %w", err)
	}
	if marker.Phase != "ready" || marker.State != "complete" {
		return config.Settings{}, errors.New("installation is incomplete; rerun init")
	}
	settings, err := config.LoadSettings(paths.Config)
	if err != nil {
		return config.Settings{}, err
	}
	return settings, nil
}

// OpenForServe holds a process lock for the full daemon lifetime so two
// foreground or service-manager instances cannot share one SQLite state.
func OpenForServe(ctx context.Context, stateDir string) (*Instance, error) {
	if err := config.EnsureStateDirectory(stateDir); err != nil {
		return nil, err
	}
	lock, err := acquireNamedLock(stateDir, ".server.lock", "another server process is already running")
	if err != nil {
		return nil, err
	}
	opened, err := Open(ctx, stateDir)
	if err != nil {
		if closeErr := lock.Close(); closeErr != nil {
			return nil, errors.Join(err, fmt.Errorf("release server lock: %w", closeErr))
		}
		return nil, err
	}
	opened.lock = lock
	return opened, nil
}

func (instance *Instance) Close() error {
	storeErr := instance.Store.Close()
	var lockErr error
	if instance.lock != nil {
		lockErr = instance.lock.Close()
		instance.lock = nil
	}
	if storeErr != nil {
		if lockErr != nil {
			return errors.Join(storeErr, lockErr)
		}
		return storeErr
	}
	return lockErr
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}
