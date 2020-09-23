package libpod

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/containers/common/pkg/config"
	"github.com/containers/libpod/v2/libpod/define"
	"github.com/containers/libpod/v2/libpod/events"
	"github.com/containers/libpod/v2/pkg/rootless"
	"github.com/containers/libpod/v2/pkg/selinux"
	"github.com/containers/storage"
	"github.com/containers/storage/pkg/stringid"
	spec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/opencontainers/runtime-tools/generate"
	"github.com/opentracing/opentracing-go"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// NewContainer creates a new container from a given OCI config.
func (r *Runtime) NewRContainer(ctx context.Context, rSpec *spec.Spec, options ...CtrCreateOption) (*Container, error) {
	r.lock.Lock()
	defer r.lock.Unlock()
	if !r.valid {
		return nil, define.ErrRuntimeStopped
	}
	return r.newRContainer(ctx, rSpec, options...)
}

func (r *Runtime) newRContainer(ctx context.Context, rSpec *spec.Spec, options ...CtrCreateOption) (*Container, error) {
	span, _ := opentracing.StartSpanFromContext(ctx, "newRContainer")
	span.SetTag("type", "runtime")
	defer span.Finish()

	ctr, err := r.initContainerVariables(rSpec, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "error initializing container variables")
	}

	for _, option := range options {
		if err := option(ctr); err != nil {
			return nil, errors.Wrapf(err, "error running container create option")
		}
	}

	return r.setupRContainer(ctx, ctr)
}

func (r *Runtime) setupRContainer(ctx context.Context, ctr *Container) (_ *Container, retErr error) {
	// Validate the container
	if err := ctr.validate(); err != nil {
		return nil, err
	}

	// Allocate a lock for the container
	lock, err := r.lockManager.AllocateLock()
	if err != nil {
		return nil, errors.Wrapf(err, "error allocating lock for new container")
	}
	ctr.lock = lock
	ctr.config.LockID = ctr.lock.ID()
	logrus.Debugf("Allocated lock %d for container %s", ctr.lock.ID(), ctr.ID())

	defer func() {
		if retErr != nil {
			if err := ctr.lock.Free(); err != nil {
				logrus.Errorf("Error freeing lock for container after creation failed: %v", err)
			}
		}
	}()

	ctr.valid = true
	ctr.state.State = define.ContainerStateConfigured
	ctr.runtime = r

	if ctr.config.OCIRuntime == "" {
		ctr.ociRuntime = r.defaultOCIRuntime
	} else {
		ociRuntime, ok := r.ociRuntimes[ctr.config.OCIRuntime]
		if !ok {
			return nil, errors.Wrapf(define.ErrInvalidArg, "requested OCI runtime %s is not available", ctr.config.OCIRuntime)
		}
		ctr.ociRuntime = ociRuntime
	}

	// Check NoCgroups support
	if ctr.config.NoCgroups {
		if !ctr.ociRuntime.SupportsNoCgroups() {
			return nil, errors.Wrapf(define.ErrInvalidArg, "requested OCI runtime %s is not compatible with NoCgroups", ctr.ociRuntime.Name())
		}
	}

	var pod *Pod
	if ctr.config.Pod != "" {
		// Get the pod from state
		pod, err = r.state.Pod(ctr.config.Pod)
		if err != nil {
			return nil, errors.Wrapf(err, "cannot add container %s to pod %s", ctr.ID(), ctr.config.Pod)
		}
	}

	if ctr.config.Name == "" {
		name, err := r.generateName()
		if err != nil {
			return nil, err
		}

		ctr.config.Name = name
	}

	// Check CGroup parent sanity, and set it if it was not set.
	// Only if we're actually configuring CGroups.
	if !ctr.config.NoCgroups {
		switch r.config.Engine.CgroupManager {
		case config.CgroupfsCgroupsManager:
			if ctr.config.CgroupParent == "" {
				if pod != nil && pod.config.UsePodCgroup {
					podCgroup, err := pod.CgroupPath()
					if err != nil {
						return nil, errors.Wrapf(err, "error retrieving pod %s cgroup", pod.ID())
					}
					if podCgroup == "" {
						return nil, errors.Wrapf(define.ErrInternal, "pod %s cgroup is not set", pod.ID())
					}
					ctr.config.CgroupParent = podCgroup
				} else {
					ctr.config.CgroupParent = CgroupfsDefaultCgroupParent
				}
			} else if strings.HasSuffix(path.Base(ctr.config.CgroupParent), ".slice") {
				return nil, errors.Wrapf(define.ErrInvalidArg, "systemd slice received as cgroup parent when using cgroupfs")
			}
		case config.SystemdCgroupsManager:
			if ctr.config.CgroupParent == "" {
				switch {
				case pod != nil && pod.config.UsePodCgroup:
					podCgroup, err := pod.CgroupPath()
					if err != nil {
						return nil, errors.Wrapf(err, "error retrieving pod %s cgroup", pod.ID())
					}
					ctr.config.CgroupParent = podCgroup
				case rootless.IsRootless():
					ctr.config.CgroupParent = SystemdDefaultRootlessCgroupParent
				default:
					ctr.config.CgroupParent = SystemdDefaultCgroupParent
				}
			} else if len(ctr.config.CgroupParent) < 6 || !strings.HasSuffix(path.Base(ctr.config.CgroupParent), ".slice") {
				return nil, errors.Wrapf(define.ErrInvalidArg, "did not receive systemd slice as cgroup parent when using systemd to manage cgroups")
			}
		default:
			return nil, errors.Wrapf(define.ErrInvalidArg, "unsupported CGroup manager: %s - cannot validate cgroup parent", r.config.Engine.CgroupManager)
		}
	}

	if ctr.restoreFromCheckpoint {
		// Remove information about bind mount
		// for new container from imported checkpoint
		g := generate.Generator{Config: ctr.config.Spec}
		g.RemoveMount("/dev/shm")
		ctr.config.ShmDir = ""
		g.RemoveMount("/etc/resolv.conf")
		g.RemoveMount("/etc/hostname")
		g.RemoveMount("/etc/hosts")
		g.RemoveMount("/run/.containerenv")
		g.RemoveMount("/run/secrets")

		// Regenerate CGroup paths so they don't point to the old
		// container ID.
		cgroupPath, err := ctr.getOCICgroupPath()
		if err != nil {
			return nil, err
		}
		g.SetLinuxCgroupsPath(cgroupPath)
	}

	// Set up storage for the container
	if err := ctr.setupRStorage(ctx); err != nil {
		return nil, err
	}
	defer func() {
		if retErr != nil {
			if err := ctr.teardownStorage(); err != nil {
				logrus.Errorf("Error removing partially-created container root filesystem: %s", err)
			}
		}
	}()

	if ctr.config.ConmonPidFile == "" {
		ctr.config.ConmonPidFile = filepath.Join(ctr.state.RunDir, "conmon.pid")
	}

	// Go through named volumes and add them.
	// If they don't exist they will be created using basic options.
	// Maintain an array of them - we need to lock them later.
	ctrNamedVolumes := make([]*Volume, 0, len(ctr.config.NamedVolumes))
	for _, vol := range ctr.config.NamedVolumes {
		isAnonymous := false
		if vol.Name == "" {
			// Anonymous volume. We'll need to create it.
			// It needs a name first.
			vol.Name = stringid.GenerateNonCryptoID()
			isAnonymous = true
		} else {
			// Check if it exists already
			dbVol, err := r.state.Volume(vol.Name)
			if err == nil {
				ctrNamedVolumes = append(ctrNamedVolumes, dbVol)
				// The volume exists, we're good
				continue
			} else if errors.Cause(err) != define.ErrNoSuchVolume {
				return nil, errors.Wrapf(err, "error retrieving named volume %s for new container", vol.Name)
			}
		}

		logrus.Debugf("Creating new volume %s for container", vol.Name)

		// The volume does not exist, so we need to create it.
		volOptions := []VolumeCreateOption{WithVolumeName(vol.Name), WithVolumeUID(ctr.RootUID()), WithVolumeGID(ctr.RootGID()), WithVolumeNeedsChown()}
		if isAnonymous {
			volOptions = append(volOptions, withSetAnon())
		}
		newVol, err := r.newVolume(ctx, volOptions...)
		if err != nil {
			return nil, errors.Wrapf(err, "error creating named volume %q", vol.Name)
		}

		ctrNamedVolumes = append(ctrNamedVolumes, newVol)
	}

	if ctr.config.LogPath == "" && ctr.config.LogDriver != define.JournaldLogging && ctr.config.LogDriver != define.NoLogging {
		ctr.config.LogPath = filepath.Join(ctr.config.StaticDir, "ctr.log")
	}

	if !MountExists(ctr.config.Spec.Mounts, "/dev/shm") && ctr.config.ShmDir == "" {
		ctr.config.ShmDir = filepath.Join(ctr.bundlePath(), "shm")
		if err := os.MkdirAll(ctr.config.ShmDir, 0700); err != nil {
			if !os.IsExist(err) {
				return nil, errors.Wrapf(err, "unable to create shm %q dir", ctr.config.ShmDir)
			}
		}
		ctr.config.Mounts = append(ctr.config.Mounts, ctr.config.ShmDir)
	}

	// Lock all named volumes we are adding ourself to, to ensure we can't
	// use a volume being removed.
	for _, namedVol := range ctrNamedVolumes {
		toLock := namedVol
		toLock.lock.Lock()
		defer toLock.lock.Unlock()
	}

	// Add the container to the state
	// TODO: May be worth looking into recovering from name/ID collisions here
	if ctr.config.Pod != "" {
		// Lock the pod to ensure we can't add containers to pods
		// being removed
		pod.lock.Lock()
		defer pod.lock.Unlock()

		if err := r.state.AddContainerToPod(pod, ctr); err != nil {
			return nil, err
		}
	} else if err := r.state.AddContainer(ctr); err != nil {
		return nil, err
	}
	ctr.newContainerEvent(events.Create)
	return ctr, nil
}

// from container_internal.go
func (c *Container) setupRStorage(ctx context.Context) error {
	span, _ := opentracing.StartSpanFromContext(ctx, "setupRStorage")
	span.SetTag("type", "container")
	defer span.Finish()

	if !c.valid {
		return errors.Wrapf(define.ErrCtrRemoved, "container %s is not valid", c.ID())
	}

	if c.state.State != define.ContainerStateConfigured {
		return errors.Wrapf(define.ErrCtrStateInvalid, "container %s must be in Configured state to have storage set up", c.ID())
	}

	// Need both an image ID and image name, plus a bool telling us whether to use the image configuration
	if c.config.Rootfs == "" && (c.config.RootfsImageID == "" || c.config.RootfsImageName == "") {
		return errors.Wrapf(define.ErrInvalidArg, "must provide image ID and image name to use an image")
	}

	options := storage.ContainerOptions{
		IDMappingOptions: storage.IDMappingOptions{
			HostUIDMapping: true,
			HostGIDMapping: true,
		},
		LabelOpts: c.config.LabelOpts,
	}
	if c.restoreFromCheckpoint {
		// If restoring from a checkpoint, the root file-system
		// needs to be mounted with the same SELinux labels as
		// it was mounted previously.
		if options.Flags == nil {
			options.Flags = make(map[string]interface{})
		}
		options.Flags["ProcessLabel"] = c.config.ProcessLabel
		options.Flags["MountLabel"] = c.config.MountLabel
	}
	if c.config.Privileged {
		privOpt := func(opt string) bool {
			for _, privopt := range []string{"nodev", "nosuid", "noexec"} {
				if opt == privopt {
					return true
				}
			}
			return false
		}

		defOptions, err := storage.GetMountOptions(c.runtime.store.GraphDriverName(), c.runtime.store.GraphOptions())
		if err != nil {
			return errors.Wrapf(err, "error getting default mount options")
		}
		var newOptions []string
		for _, opt := range defOptions {
			if !privOpt(opt) {
				newOptions = append(newOptions, opt)
			}
		}
		options.MountOpts = newOptions
	}

	c.setupStorageMapping(&options.IDMappingOptions, &c.config.IDMappings)

	containerInfo, err := c.runtime.storageService.CreateContainerStorage(ctx, c.runtime.imageContext, c.config.RootfsImageName, c.config.RootfsImageID, c.config.Name, c.config.ID, options)
	if err != nil {
		return errors.Wrapf(err, "error creating container storage")
	}

	c.config.IDMappings.UIDMap = containerInfo.UIDMap
	c.config.IDMappings.GIDMap = containerInfo.GIDMap

	processLabel := containerInfo.ProcessLabel
	switch {
	case c.ociRuntime.SupportsKVM():
		processLabel, err = selinux.KVMLabel(processLabel)
		if err != nil {
			return err
		}
	case c.config.Systemd:
		processLabel, err = selinux.InitLabel(processLabel)
		if err != nil {
			return err
		}
	}

	c.config.ProcessLabel = processLabel
	c.config.MountLabel = containerInfo.MountLabel
	c.config.StaticDir = containerInfo.Dir
	c.state.RunDir = containerInfo.RunDir

	if len(c.config.IDMappings.UIDMap) != 0 || len(c.config.IDMappings.GIDMap) != 0 {
		if err := os.Chown(containerInfo.RunDir, c.RootUID(), c.RootGID()); err != nil {
			return err
		}

		if err := os.Chown(containerInfo.Dir, c.RootUID(), c.RootGID()); err != nil {
			return err
		}
	}

	// Set the default Entrypoint and Command
	if containerInfo.Config != nil {
		if c.config.Entrypoint == nil {
			c.config.Entrypoint = containerInfo.Config.Config.Entrypoint
		}
		if c.config.Command == nil {
			c.config.Command = containerInfo.Config.Config.Cmd
		}
	}

	artifacts := filepath.Join(c.config.StaticDir, artifactsDir)
	if err := os.MkdirAll(artifacts, 0755); err != nil {
		return errors.Wrapf(err, "error creating artifacts directory %q", artifacts)
	}

	return nil
}
