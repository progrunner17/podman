package containers

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/containers/common/pkg/config"
	"github.com/containers/image/v5/image"
	"github.com/containers/image/v5/transports/alltransports"
	"github.com/containers/image/v5/types"
	"github.com/containers/libpod/v2/cmd/podman/common"
	"github.com/containers/libpod/v2/cmd/podman/registry"
	"github.com/containers/libpod/v2/libpod"
	"github.com/containers/libpod/v2/libpod/define"
	"github.com/containers/libpod/v2/libpod/events"
	limage "github.com/containers/libpod/v2/libpod/image"
	"github.com/containers/libpod/v2/pkg/domain/entities"
	"github.com/containers/libpod/v2/pkg/domain/infra/abi"
	"github.com/containers/libpod/v2/pkg/domain/infra/abi/terminal"
	envLib "github.com/containers/libpod/v2/pkg/env"
	"github.com/containers/libpod/v2/pkg/errorhandling"
	"github.com/containers/libpod/v2/pkg/rootless"
	"github.com/containers/libpod/v2/pkg/specgen"
	"github.com/containers/libpod/v2/pkg/specgen/generate"
	"github.com/containers/libpod/v2/pkg/util"
	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	spec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/xerrors"
)

var (
	rrunDescription = "Runs a command in a new container from the given remote image"
	rrunCommand     = &cobra.Command{
		Args:  cobra.MinimumNArgs(1),
		Use:   "rrun [flags] IMAGE [COMMAND [ARG...]]",
		Short: "Run a command in a new container from remote image",
		Long:  rrunDescription,
		RunE:  rrun,
		Example: `podman rrun imageID ls -alF /etc
  podman rrun --network=host imageID dnf -y install java
  podman rrun --volume /var/hostdir:/var/ctrdir -i -t fedora /bin/bash`,
	}

//
// 	containerRRunCommand = &cobra.Command{
// 		Args:  cobra.MinimumNArgs(1),
// 		Use:   rrunCommand.Use,
// 		Short: rrunCommand.Short,
// 		Long:  rrunCommand.Long,
// 		RunE:  rrunCommand.RunE,
// 		Example: `podman container rrun imageID ls -alF /etc
// 	podman container rrun --network=host imageID dnf -y install java
// 	podman container rrun --volume /var/hostdir:/var/ctrdir -i -t fedora /bin/bash`,
// 	}
)

var (
	//[TODO]: ContainerRunOptionsを複製すべきか検討
	rrunOpts = entities.ContainerRunOptions{
		OutputStream: os.Stdout,
		InputStream:  os.Stdin,
		ErrorStream:  os.Stderr,
	}
	rrunRmi bool
)

func rrunFlags(flags *pflag.FlagSet) {
	flags.SetInterspersed(false)
	flags.AddFlagSet(common.GetCreateFlags(&cliVals))
	flags.AddFlagSet(common.GetNetFlags())
	flags.SetNormalizeFunc(common.AliasFlags)
	flags.BoolVar(&rrunOpts.SigProxy, "sig-proxy", true, "Proxy received signals to the process")
	flags.BoolVar(&rrunRmi, "rmi", false, "Remove container image unless used by other containers")

	if registry.IsRemote() {
		_ = flags.MarkHidden("authfile")
		_ = flags.MarkHidden("env-host")
		_ = flags.MarkHidden("http-proxy")
	}
	// Not sure we want these exposed yet.  If we do, they need to be documented in man pages
	_ = flags.MarkHidden("override-arch")
	_ = flags.MarkHidden("override-os")
}

func init() {
	registry.Commands = append(registry.Commands, registry.CliCommand{
		Mode:    []entities.EngineMode{entities.ABIMode, entities.TunnelMode},
		Command: rrunCommand,
	})
	flags := rrunCommand.Flags()
	rrunFlags(flags)

	// 	registry.Commands = append(registry.Commands, registry.CliCommand{
	// 		Mode:    []entities.EngineMode{entities.ABIMode, entities.TunnelMode},
	// 		Command: containerRRunCommand,
	// 		Parent:  containerCmd,
	// 	})
	//
	// 	containerRRunFlags := containerRRunCommand.Flags()
	// 	rrunFlags(containerRRunFlags)
}

func rrun(cmd *cobra.Command, args []string) error {
	var err error
	cliVals.Net, err = common.NetFlagsToNetOptions(cmd)
	if err != nil {
		return err
	}

	if rootless.IsRootless() && !registry.IsRemote() {
		userspec := strings.SplitN(cliVals.User, ":", 2)[0]
		if uid, err := strconv.ParseInt(userspec, 10, 32); err == nil {
			if err := util.CheckRootlessUIDRange(int(uid)); err != nil {
				return err
			}
		}
	}

	if af := cliVals.Authfile; len(af) > 0 {
		if _, err := os.Stat(af); err != nil {
			return errors.Wrapf(err, "error checking authfile path %s", af)
		}
	}
	cidFile, err := openCidFile(cliVals.CIDFile)
	if err != nil {
		return err
	}

	if cidFile != nil {
		defer errorhandling.CloseQuiet(cidFile)
		defer errorhandling.SyncQuiet(cidFile)
	}
	rrunOpts.Rm = cliVals.Rm
	if err := createInit(cmd); err != nil {
		return err
	}

	imageName := args[0]
	var ociCfg *v1.Image
	var ctrMntDir string
	logrus.Info("[DEBUG] prepareRemoteImage!!!")
	if !cliVals.RootFS {
		ctx := registry.GetContext()
		img, err := getImage(ctx, "docker://"+args[0])
		if err != nil {
			logrus.Fatalf("parse image source: %+v", err)
		}
		ctrMntDirTmp, finalize, err := prepareRemoteImage(ctx, img, 2)
		logrus.Info("[DEBUG] prepareRemoteImage")
		if err != nil {
			logrus.Errorf("%+v", err)
		}
		ctrMntDir = ctrMntDirTmp
		defer finalize()
		ociCfg, err = img.OCIConfig(registry.GetContext())

		// NOTE: llpfs1
		// 		name, ociCfg, err = pullRImage(args[0])
		//TODO: 2
		// 		name, err := pullImage(args[0])
		if err != nil {
			return err
		}
		// 		imageName = name
		imageName = ""
	}

	if cliVals.Replace {
		if err := replaceContainer(cliVals.Name); err != nil {
			return err
		}
	}

	// If -i is not set, clear stdin
	if !cliVals.Interactive {
		rrunOpts.InputStream = nil
	}

	// If attach is set, clear stdin/stdout/stderr and only attach requested
	if cmd.Flag("attach").Changed {
		rrunOpts.OutputStream = nil
		rrunOpts.ErrorStream = nil
		if !cliVals.Interactive {
			rrunOpts.InputStream = nil
		}

		for _, stream := range cliVals.Attach {
			switch strings.ToLower(stream) {
			case "stdout":
				rrunOpts.OutputStream = os.Stdout
			case "stderr":
				rrunOpts.ErrorStream = os.Stderr
			case "stdin":
				rrunOpts.InputStream = os.Stdin
			default:
				return errors.Wrapf(define.ErrInvalidArg, "invalid stream %q for --attach - must be one of stdin, stdout, or stderr", stream)
			}
		}
	}
	rrunOpts.Detach = cliVals.Detach
	rrunOpts.DetachKeys = cliVals.DetachKeys
	// [TODO]: remote imageを使ってNewSpecGeneratorを動かせるようにする
	s := specgen.NewSpecGenerator("", cliVals.RootFS)
	// NOTE: llpfs1
	// 	ctrMntDir, ctrRootDir, err := createRootFSMountPoint(imageName)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	defer finalizeMountPoint(ctrMntDir, ctrRootDir)

	s.Rootfs = ctrMntDir
	// 	s.Rootfs = "/home/vagrant/hello-world/hello-root"
	logrus.WithField("rootfs", s.Rootfs).Info("[DEBUG]")
	s.Command = ociCfg.Config.Cmd
	s.Entrypoint = ociCfg.Config.Entrypoint
	envs, err := envLib.ParseSlice(ociCfg.Config.Env)
	s.Env = envLib.Join(s.Env, envs)
	s.WorkDir = ociCfg.Config.WorkingDir
	if err := common.FillOutSpecGen(s, &cliVals, args); err != nil {
		return err
	}
	rrunOpts.Spec = s

	if _, err := createPodIfNecessary(s, cliVals.Net); err != nil {
		return err
	}

	report, err := containerRRun(registry.GetContext(), registry.ContainerEngine(), rrunOpts)
	// report.ExitCode is set by ContainerRun even it it returns an error
	if report != nil {
		registry.SetExitCode(report.ExitCode)
	}
	if err != nil {
		return err
	}
	if cidFile != nil {
		_, err = cidFile.WriteString(report.Id)
		if err != nil {
			logrus.Error(err)
		}
	}

	if cliVals.Detach {
		fmt.Println(report.Id)
		return nil
	}
	if rrunRmi {
		_, rmErrors := registry.ImageEngine().Remove(registry.GetContext(), []string{imageName}, entities.ImageRemoveOptions{})
		if len(rmErrors) > 0 {
			logrus.Errorf("%s", errors.Wrapf(errorhandling.JoinErrors(rmErrors), "failed removing image"))
		}
	}
	return nil
}

func pullRImage(imageName string) (string, *v1.Image, error) {
	var ociCfg *v1.Image
	pullPolicy, err := config.ValidatePullPolicy(cliVals.Pull)
	if err != nil {
		return "", nil, err
	}

	// Check if the image is missing and hence if we need to pull it.
	imageMissing := true
	imageRef, err := alltransports.ParseImageName(imageName)
	logrus.WithField("imageRef", imageRef).Info("[DEBUG]") // => nil
	// 	switch {
	// 	case err != nil:
	// 		// Assume we specified a local image withouth the explicit storage transport.
	// 		fallthrough
	//
	// 	case imageRef.Transport().Name() == storage.Transport.Name():
	// 		br, err := registry.ImageEngine().Exists(registry.GetContext(), imageName)
	// 		if err != nil {
	// 			return "", err
	// 		}
	// 		imageMissing = !br.Value
	// 	}

	if imageMissing || pullPolicy == config.PullImageAlways {
		if pullPolicy == config.PullImageNever {
			return "", nil, errors.Wrapf(define.ErrNoSuchImage, "unable to find a name and tag match for %s in repotags", imageName)
		}
		is, err := parseImageSource(registry.GetContext(), "docker://"+imageName)
		if err != nil {
			logrus.Panicf("[DEBUG] parseImageSource failed %v", err)
			return "", nil, err
		}
		// 		logrus.WithField("imageSource", is).Info("[DEBUG]")
		logrus.WithField("imageSource", is.Reference().DockerReference()).Info("[DEBUG]")

		img, err := image.FromUnparsedImage(registry.GetContext(), nil, image.UnparsedInstance(is, nil))
		if err != nil {
			logrus.Panicf("Error parsing manifest for image: %v", err)
		}
		// 		logrus.WithField("image", img).Info("[DEBUG]")
		for i, l := range img.LayerInfos() {
			logrus.WithFields(logrus.Fields{
				"idx":     i,
				"digest":  l.Digest.Encoded(),
				"digest2": l.Digest.Hex(),
				"digest3": l.Digest.String(),
				"type":    l.MediaType,
				"size":    l.Size,
			}).Info("[DEBUG]")
		}

		info, err := img.Inspect(registry.GetContext())
		if err != nil {
			logrus.Panicf("Inspect image: %v", err)
		}
		logrus.WithField("info", info).Info("[DEBUG]")
		if err != nil {
			logrus.Panicf("LayerInfosForCopy: %v", err)
		}
		ociCfg, err = img.OCIConfig(registry.GetContext())
		if err != nil {
			logrus.Panicf("get OCIConfig image: %v", err)
		}
		// 		logrus.WithField("cmd", ociCfg.Config.Cmd).Info("[DEBUG]")
		// 		logrus.WithField("entrypoint", ociCfg.Config.Entrypoint).Info("[DEBUG]")
		// 		logrus.WithField("env", ociCfg.Config.Env).Info("[DEBUG]")
		// 		logrus.WithField("workdir", ociCfg.Config.WorkingDir).Info("[DEBUG]")
		// 		logrus.WithField("ports", ociCfg.Config.ExposedPorts).Info("[DEBUG]")
		// 		logrus.WithField("labels", ociCfg.Config.Labels).Info("[DEBUG]")
		// 		logrus.WithField("signals", ociCfg.Config.StopSignal).Info("[DEBUG]")
		// 		logrus.WithField("user", ociCfg.Config.User).Info("[DEBUG]")
		// 		logrus.WithField("volumes", ociCfg.Config.Volumes).Info("[DEBUG]")
		// 		logrus.WithField("rootfs type", ociCfg.RootFS.Type).Info("[DEBUG]")
		// 		for i, digest := range ociCfg.RootFS.DiffIDs {
		// 			logrus.WithField("i", i).WithField("hex", digest.Hex()).WithField("string", digest.String()).WithField("algorithm", digest.Algorithm().String()).Info("[DEBUG]")
		// 		}
		// 		pullReport, pullErr := registry.ImageEngine().Pull(registry.GetContext(), imageName, entities.ImagePullOptions{
		// 			Authfile:     cliVals.Authfile,
		// 			Quiet:        cliVals.Quiet,
		// 			OverrideArch: cliVals.OverrideArch,
		// 			OverrideOS:   cliVals.OverrideOS,
		// 		})
		// 		if pullErr != nil {
		// 			return "", pullErr
		// 		}
		// 		imageName = pullReport.Images[0]
	}
	return imageName, ociCfg, nil
}

func parseImageSource(ctx context.Context, name string) (types.ImageSource, error) {
	ref, err := alltransports.ParseImageName(name)
	if err != nil {
		return nil, err
	}
	return ref.NewImageSource(ctx, &types.SystemContext{})
}

// [TODO]: manifestやconfigをこの関数に渡したい
func containerRRun(ctx context.Context, raw_ic entities.ContainerEngine, opts entities.ContainerRunOptions) (*entities.ContainerRunReport, error) {
	ic, ok := raw_ic.(*abi.ContainerEngine)
	if !ok {
		return nil, fmt.Errorf("ContainerEngine needs abi.ContainerEngine")
	}

	// 	opts.Spec.Image = ""
	// 			s.HealthConfig, err = newImage.GetHealthCheck(ctx)
	// 			stopSignal, err := newImage.StopSignal(ctx)
	// 			sig, err := signal.ParseSignalNameOrNumber(stopSignal)
	// 			s.StopSignal = &sig
	// 		imageEnvs, err := newImage.Env(ctx)
	// 		envs, err = envLib.ParseSlice(imageEnvs)
	// 	s.Env = envLib.Join(envLib.Join(defaultEnvs, envs), s.Env)
	// 		labels, err := newImage.Labels(ctx)
	// 				s.Labels[k] = v
	// 		imgAnnotations, err := newImage.Annotations(ctx)
	// 			annotations[k] = v
	// 	s.Annotations = annotations
	// 			workingDir, err := newImage.WorkingDir(ctx)
	// 			s.WorkDir = workingDir
	// 		s.User, err = newImage.User(ctx)
	// [TODO]: remote imageを使えるように変更
	// annotationsはあとからセットする方がよさそう？
	// それ以外は、generate.CompleteSpec で十分なはず
	// @pkg/specgen/generate/container.go
	warn, err := generate.CompleteSpec(ctx, ic.Libpod, opts.Spec)
	if err != nil {
		return nil, err
	}
	// Print warnings
	for _, w := range warn {
		fmt.Fprintf(os.Stderr, "%s\n", w)
	}
	// [TODO]: remote imageを使うように変更
	ctr, err := makeContainer(ctx, ic.Libpod, opts.Spec)
	if err != nil {
		return nil, err
	}

	var joinPod bool
	if len(ctr.PodID()) > 0 {
		joinPod = true
	}
	report := entities.ContainerRunReport{Id: ctr.ID()}

	if logrus.GetLevel() == logrus.DebugLevel {
		cgroupPath, err := ctr.CGroupPath()
		if err == nil {
			logrus.Debugf("container %q has CgroupParent %q", ctr.ID(), cgroupPath)
		}
	}
	if opts.Detach {
		// if the container was created as part of a pod, also start its dependencies, if any.
		// [TODO]: StartAttachCtrと同様に修正
		if err := ctr.Start(ctx, joinPod); err != nil {
			// This means the command did not exist
			report.ExitCode = define.ExitCode(err)
			return &report, err
		}

		return &report, nil
	}

	// if the container was created as part of a pod, also start its dependencies, if any.
	if err := terminal.StartAttachCtr(ctx, ctr, opts.OutputStream, opts.ErrorStream, opts.InputStream, opts.DetachKeys, opts.SigProxy, true, joinPod); err != nil {
		// We've manually detached from the container
		// Do not perform cleanup, or wait for container exit code
		// Just exit immediately
		if errors.Cause(err) == define.ErrDetach {
			report.ExitCode = 0
			return &report, nil
		}
		if opts.Rm {
			if deleteError := ic.Libpod.RemoveContainer(ctx, ctr, true, false); deleteError != nil {
				logrus.Debugf("unable to remove container %s after failing to start and attach to it", ctr.ID())
			}
		}
		if errors.Cause(err) == define.ErrWillDeadlock {
			logrus.Debugf("Deadlock error on %q: %v", ctr.ID(), err)
			report.ExitCode = define.ExitCode(err)
			return &report, errors.Errorf("attempting to start container %s would cause a deadlock; please run 'podman system renumber' to resolve", ctr.ID())
		}
		report.ExitCode = define.ExitCode(err)
		return &report, err
	}

	if ecode, err := ctr.Wait(); err != nil {
		if errors.Cause(err) == define.ErrNoSuchCtr {
			// Check events
			event, err := ic.Libpod.GetLastContainerEvent(ctx, ctr.ID(), events.Exited)
			if err != nil {
				logrus.Errorf("Cannot get exit code: %v", err)
				report.ExitCode = define.ExecErrorCodeNotFound
			} else {
				report.ExitCode = event.ContainerExitCode
			}
		}
	} else {
		report.ExitCode = int(ecode)
	}
	if opts.Rm {
		if err := ic.Libpod.RemoveContainer(ctx, ctr, false, true); err != nil {
			if errors.Cause(err) == define.ErrNoSuchCtr ||
				errors.Cause(err) == define.ErrCtrRemoved {
				logrus.Warnf("Container %s does not exist: %v", ctr.ID(), err)
			} else {
				logrus.Errorf("Error removing container %s: %v", ctr.ID(), err)
			}
		}
	}
	return &report, nil
}

func createContainerOptions(ctx context.Context, rt *libpod.Runtime, s *specgen.SpecGenerator, pod *libpod.Pod, volumes []*specgen.NamedVolume, img *limage.Image, command []string) ([]libpod.CtrCreateOption, error) {
	var options []libpod.CtrCreateOption
	var err error

	if s.Stdin {
		options = append(options, libpod.WithStdin())
	}

	useSystemd := false
	switch s.Systemd {
	case "always":
		useSystemd = true
	case "false":
		break
	case "", "true":
		if len(command) == 0 {
			command, err = img.Cmd(ctx)
			if err != nil {
				return nil, err
			}
		}

		if len(command) > 0 {
			useSystemdCommands := map[string]bool{
				"/sbin/init":           true,
				"/usr/sbin/init":       true,
				"/usr/local/sbin/init": true,
			}
			if useSystemdCommands[command[0]] || (filepath.Base(command[0]) == "systemd") {
				useSystemd = true
			}
		}
	default:
		return nil, errors.Wrapf(err, "invalid value %q systemd option requires 'true, false, always'", s.Systemd)
	}
	logrus.Debugf("using systemd mode: %t", useSystemd)
	if useSystemd {
		// is StopSignal was not set by the user then set it to systemd
		// expected StopSigal
		if s.StopSignal == nil {
			stopSignal, err := util.ParseSignal("RTMIN+3")
			if err != nil {
				return nil, errors.Wrapf(err, "error parsing systemd signal")
			}
			s.StopSignal = &stopSignal
		}

		options = append(options, libpod.WithSystemd())
	}
	if len(s.Name) > 0 {
		logrus.Debugf("setting container name %s", s.Name)
		options = append(options, libpod.WithName(s.Name))
	}
	if pod != nil {
		logrus.Debugf("adding container to pod %s", pod.Name())
		options = append(options, rt.WithPod(pod))
	}
	destinations := []string{}
	// Take all mount and named volume destinations.
	for _, mount := range s.Mounts {
		destinations = append(destinations, mount.Destination)
	}
	for _, volume := range volumes {
		destinations = append(destinations, volume.Dest)
	}
	options = append(options, libpod.WithUserVolumes(destinations))

	if len(volumes) != 0 {
		var vols []*libpod.ContainerNamedVolume
		for _, v := range volumes {
			vols = append(vols, &libpod.ContainerNamedVolume{
				Name:    v.Name,
				Dest:    v.Dest,
				Options: v.Options,
			})
		}
		options = append(options, libpod.WithNamedVolumes(vols))
	}

	if s.Command != nil {
		options = append(options, libpod.WithCommand(s.Command))
	}
	if s.Entrypoint != nil {
		options = append(options, libpod.WithEntrypoint(s.Entrypoint))
	}
	// If the user did not set an workdir but the image did, ensure it is
	// created.
	if s.WorkDir == "" && img != nil {
		options = append(options, libpod.WithCreateWorkingDir())
	}
	if s.StopSignal != nil {
		options = append(options, libpod.WithStopSignal(*s.StopSignal))
	}
	if s.StopTimeout != nil {
		options = append(options, libpod.WithStopTimeout(*s.StopTimeout))
	}
	if s.LogConfiguration != nil {
		if len(s.LogConfiguration.Path) > 0 {
			options = append(options, libpod.WithLogPath(s.LogConfiguration.Path))
		}
		if len(s.LogConfiguration.Options) > 0 && s.LogConfiguration.Options["tag"] != "" {
			// Note: I'm really guessing here.
			options = append(options, libpod.WithLogTag(s.LogConfiguration.Options["tag"]))
		}

		if len(s.LogConfiguration.Driver) > 0 {
			options = append(options, libpod.WithLogDriver(s.LogConfiguration.Driver))
		}
	}

	// Security options
	if len(s.SelinuxOpts) > 0 {
		options = append(options, libpod.WithSecLabels(s.SelinuxOpts))
	}
	options = append(options, libpod.WithPrivileged(s.Privileged))

	// 	// Get namespace related options
	// 	namespaceOptions, err := namespaceOptions(ctx, s, rt, pod, img)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	options = append(options, namespaceOptions...)

	if len(s.ConmonPidFile) > 0 {
		options = append(options, libpod.WithConmonPidFile(s.ConmonPidFile))
	}
	options = append(options, libpod.WithLabels(s.Labels))
	if s.ShmSize != nil {
		options = append(options, libpod.WithShmSize(*s.ShmSize))
	}
	if s.Rootfs != "" {
		options = append(options, libpod.WithRootFS(s.Rootfs))
	}
	// Default used if not overridden on command line

	if s.RestartPolicy != "" {
		if s.RestartRetries != nil {
			options = append(options, libpod.WithRestartRetries(*s.RestartRetries))
		}
		options = append(options, libpod.WithRestartPolicy(s.RestartPolicy))
	}

	if s.ContainerHealthCheckConfig.HealthConfig != nil {
		options = append(options, libpod.WithHealthCheck(s.ContainerHealthCheckConfig.HealthConfig))
		logrus.Debugf("New container has a health check")
	}
	return options, nil
}

func makeCommand(ctx context.Context, s *specgen.SpecGenerator, img *limage.Image, rtc *config.Config) ([]string, error) {
	finalCommand := []string{}

	entrypoint := s.Entrypoint
	if entrypoint == nil && img != nil {
		newEntry, err := img.Entrypoint(ctx)
		if err != nil {
			return nil, err
		}
		entrypoint = newEntry
	}

	finalCommand = append(finalCommand, entrypoint...)

	// Only use image command if the user did not manually set an
	// entrypoint.
	command := s.Command
	if command == nil && img != nil && s.Entrypoint == nil {
		newCmd, err := img.Cmd(ctx)
		if err != nil {
			return nil, err
		}
		command = newCmd
	}

	finalCommand = append(finalCommand, command...)

	if len(finalCommand) == 0 {
		return nil, errors.Errorf("no command or entrypoint provided, and no CMD or ENTRYPOINT from image")
	}

	if s.Init {
		initPath := s.InitPath
		if initPath == "" && rtc != nil {
			initPath = rtc.Engine.InitPath
		}
		if initPath == "" {
			return nil, errors.Errorf("no path to init binary found but container requested an init")
		}
		finalCommand = append([]string{"/dev/init", "--"}, finalCommand...)
	}

	return finalCommand, nil
}

func makeContainer(ctx context.Context, rt *libpod.Runtime, s *specgen.SpecGenerator) (*libpod.Container, error) {
	rtc, err := rt.GetConfig()
	if err != nil {
		return nil, err
	}

	// If joining a pod, retrieve the pod for use.
	var pod *libpod.Pod
	if s.Pod != "" {
		pod, err = rt.LookupPod(s.Pod)
		if err != nil {
			return nil, errors.Wrapf(err, "error retrieving pod %s", s.Pod)
		}
	}

	// Set defaults for unset namespaces
	if s.PidNS.IsDefault() {
		defaultNS, err := generate.GetDefaultNamespaceMode("pid", rtc, pod)
		if err != nil {
			return nil, err
		}
		s.PidNS = defaultNS
	}
	if s.IpcNS.IsDefault() {
		defaultNS, err := generate.GetDefaultNamespaceMode("ipc", rtc, pod)
		if err != nil {
			return nil, err
		}
		s.IpcNS = defaultNS
	}
	if s.UtsNS.IsDefault() {
		defaultNS, err := generate.GetDefaultNamespaceMode("uts", rtc, pod)
		if err != nil {
			return nil, err
		}
		s.UtsNS = defaultNS
	}
	if s.UserNS.IsDefault() {
		defaultNS, err := generate.GetDefaultNamespaceMode("user", rtc, pod)
		if err != nil {
			return nil, err
		}
		s.UserNS = defaultNS
	}
	if s.NetNS.IsDefault() {
		defaultNS, err := generate.GetDefaultNamespaceMode("net", rtc, pod)
		if err != nil {
			return nil, err
		}
		s.NetNS = defaultNS
	}
	if s.CgroupNS.IsDefault() {
		defaultNS, err := generate.GetDefaultNamespaceMode("cgroup", rtc, pod)
		if err != nil {
			return nil, err
		}
		s.CgroupNS = defaultNS
	}

	options := []libpod.CtrCreateOption{}
	if s.ContainerCreateCommand != nil {
		options = append(options, libpod.WithCreateCommand(s.ContainerCreateCommand))
	}

	var newImage *limage.Image
	if s.Rootfs != "" {
		options = append(options, libpod.WithRootFS(s.Rootfs))
	} else {
		// 		newImage, err = rt.ImageRuntime().NewFromLocal(s.Image)
		// 		if err != nil {
		// 			return nil, err
		// 		}
		// 		imgName := s.Image
		// 		names := newImage.Names()
		// 		if len(names) > 0 {
		// 			imgName = names[0]
		// 		}
		// 		options = append(options, libpod.WithRootFSFromImage(newImage.ID(), imgName, s.Image))
		logrus.Fatal("specify Rootfs!!!")
	}
	if err := s.Validate(); err != nil {
		return nil, errors.Wrap(err, "invalid config provided")
	}

	// 	finalMounts, finalVolumes, err := finalizeMounts(ctx, s, rt, rtc, newImage)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	finalMounts := make([]spec.Mount, 0, 0)
	finalVolumes := make([]*specgen.NamedVolume, 0, 0)

	// [TODO]:
	command, err := makeCommand(ctx, s, newImage, rtc)
	if err != nil {
		return nil, err
	}

	// [TODO]:
	opts, err := createContainerOptions(ctx, rt, s, pod, finalVolumes, newImage, command)
	if err != nil {
		return nil, err
	}
	options = append(options, opts...)

	exitCommandArgs, err := generate.CreateExitCommandArgs(rt.StorageConfig(), rtc, logrus.IsLevelEnabled(logrus.DebugLevel), s.Remove, false)
	if err != nil {
		return nil, err
	}
	options = append(options, libpod.WithExitCommand(exitCommandArgs))

	// newImageはsecurityConfigureGeneratorへの引数としてのみ使われる
	runtimeSpec, err := generate.SpecGenToOCI(ctx, s, rt, rtc, newImage, finalMounts, pod, command)
	if err != nil {
		return nil, err
	}
	return rt.NewRContainer(ctx, runtimeSpec, options...)
}

// 呼び出した後に、deferでfinalizeMountPointする
func createRootFSMountPoint(image string) (mntDir string, rootDir string, err error) {
	parentDir := os.TempDir() // /tmp
	rootDir, err = ioutil.TempDir(parentDir, "llpfs-*-root")
	if err != nil {
		return "", "", fmt.Errorf("failed to create dir for mntpoint: %v", err)
	}
	mntDir = rootDir + "/mnt"
	workDir := rootDir + "/work"
	upperDir := rootDir + "/upper"
	lockFile := rootDir + "/lock"
	if err = os.Mkdir(mntDir, 0755); err != nil {
		return "", rootDir, fmt.Errorf("failed to create dir for mntpoint: %v", err)
	}
	if err = os.Mkdir(workDir, 0755); err != nil {
		return "", rootDir, fmt.Errorf("failed to create dir for work dir: %v", err)
	}
	if err = os.Mkdir(upperDir, 0755); err != nil {
		return "", rootDir, fmt.Errorf("failed to create dir for upper dir: %v", err)
	}

	//llpfs -d --debug -o remote_image=alpine,workdir=./work,upperdir=./upper,src_type=remote ./mnt
	cmd := osexec.Command("llpfs")
	// 	cmd.Stderr = os.Stderr
	// 各種設定
	cmd.Args = append(cmd.Args, "-d")
	cmd.Args = append(cmd.Args, "--debug")

	registry := "docker.io"
	slice := strings.Split(image, "/")
	if len(slice) > 2 {
		logrus.Panic()
	} else if len(slice) == 2 {
		registry = slice[0]
		image = slice[1]
	}
	opts := "-o"
	opts += fmt.Sprintf("remote_registry=%s,", registry)
	opts += fmt.Sprintf("remote_image=%s,", image)
	opts += fmt.Sprintf("workdir=%s,", workDir)
	opts += fmt.Sprintf("upperdir=%s,", upperDir)
	opts += fmt.Sprintf("lockfile=%s,", lockFile)
	opts += "src_type=remote"
	cmd.Args = append(cmd.Args, opts)
	cmd.Args = append(cmd.Args, mntDir)
	logrus.WithField("opts", cmd.Args).Infof("[DEBUG]")
	err = cmd.Start()
	if err != nil {
		return "", rootDir, fmt.Errorf("failed to execute llpfs: %v", err)
	}

	for {
		lockFp, err := os.Open(lockFile)
		if err == nil {
			lockFp.Close()
			break
		}
	}
	// 	time.Sleep(time.Millisecond * 5000)
	return mntDir, rootDir, nil
}

func finalizeMountPoint(mntPoint, rootDir string) error {
	cmd := osexec.Command("fusermount3")
	cmd.Args = append(cmd.Args, "-u")
	cmd.Args = append(cmd.Args, mntPoint)
	err := cmd.Run()
	if err != nil {
		logrus.Errorf("failed to unmount %s: %v", mntPoint, err)
		return err
	}
	// 	err = os.RemoveAll(rootDir)
	// 	if err != nil {
	// 		logrus.Errorf("failed to remove %s: %v", mntPoint, err)
	// 		return err
	// 	}
	return nil
}

type layerInfo struct {
	key      string
	path     string
	pullFunc func() error
}
type pullInfo struct {
	layerInfo *layerInfo
	Conn      net.Conn
}

func prepareRemoteImage(ctx context.Context, img types.Image, numPullThreads int) (string, func(), error) {
	wg := new(sync.WaitGroup)
	pichan := make(chan *pullInfo)
	liMap := make(map[string]*layerInfo)
	tmpDir := os.TempDir()
	layersRootDir, err := ioutil.TempDir(tmpDir, "llpfs2-*-root")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create dir for mntpoint: %v", err)
	}
	sockPath := filepath.Join(layersRootDir, "llpfs2.socket")
	mntDir := filepath.Join(layersRootDir, "mnt")
	workDir := filepath.Join(layersRootDir, "work")
	upperDir := filepath.Join(layersRootDir, "upper")

	ctx, cancel := context.WithCancel(ctx)

	if err = os.Mkdir(mntDir, 0755); err != nil {
		return "", nil, fmt.Errorf("failed to create dir for mntpoint: %v", err)
	}
	if err = os.Mkdir(workDir, 0755); err != nil {
		return "", nil, fmt.Errorf("failed to create dir for work dir: %v", err)
	}
	if err = os.Mkdir(upperDir, 0755); err != nil {
		return "", nil, fmt.Errorf("failed to create dir for upper dir: %v", err)
	}

	for i := 0; i < numPullThreads; i++ {
		wg.Add(1)
		go pullThread(ctx, i, pichan, wg)
	}

	refStr := img.Reference().DockerReference().String()
	tagPos := strings.LastIndex(refStr, ":")
	repoPos := strings.Index(refStr, "/")
	repoName := refStr[0:repoPos]
	imageName := refStr[repoPos+1 : tagPos]

	var lowerLayers, tmpLayers []string
	for _, l := range img.LayerInfos() {
		li := new(layerInfo)
		digest := &l.Digest
		url := fmt.Sprintf("http://%s/v2/%s/blobs/%s", repoName, imageName, digest.String()) // 最後の/を忘れずに
		li.key = digest.Hex()
		li.path = filepath.Join(layersRootDir, li.key, "diff")
		if err = os.MkdirAll(li.path, 0755); err != nil {
			return "", nil, fmt.Errorf("failed to create dir for layer dir: %v", err)
		}

		li.pullFunc = generateLayerPullFunc(url, li.path, digest)
		liMap[li.key] = li
		logrus.WithFields(logrus.Fields{
			"key":  li.key,
			"len":  len(li.key),
			"path": li.path,
		}).Info("append layer")
		tmpLayers = append(tmpLayers, fmt.Sprintf("//unix_wait+%s+%s", li.key, li.path))
	}

	for i := len(tmpLayers) - 1; i >= 0; i-- {
		lowerLayers = append(lowerLayers, tmpLayers[i])
	}

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		logrus.Fatalf("listen path %s: %v", sockPath, err)
	}

	cmd := osexec.Command("llpfs2")
	cmd.Stderr = os.Stderr
	// 	cmd.Args = append(cmd.Args, "-d")
	// 	cmd.Args = append(cmd.Args, "--debug")

	opts := "-o"
	opts += fmt.Sprintf("workdir=%s,", workDir)
	opts += fmt.Sprintf("upperdir=%s,", upperDir)
	opts += fmt.Sprintf("lowerdir=%s,", strings.Join(lowerLayers, "$"))
	opts += fmt.Sprintf("socket_path=%s,", sockPath)
	opts += "log_level=trace,"
	opts += "fast_ino=1,"
	opts += "log_file=./llpfs2_log,"
	opts += "delims=\"$\","
	opts += "use_upmost"
	cmd.Args = append(cmd.Args, opts)
	cmd.Args = append(cmd.Args, mntDir)
	err = cmd.Run()
	if err != nil {
		return "", nil, fmt.Errorf("failed to execute llpfs: %v", err)
	}

	for i := 0; i < len(liMap); i++ {
		conn, err := listener.Accept()
		logrus.Info("Accept socket")
		if err != nil {
			return "", nil, xerrors.Errorf("accept error: %w", err)
		}
		wg.Add(1)
		go waitRequest(ctx, conn, pichan, wg, liMap)
	}

	finalize := func() {
		logrus.Info("start finalize")
		cancel()
		logrus.Info("canceled")
		wg.Wait()
		logrus.Info("wg.Wait")
		cmd := osexec.Command("fusermount3")
		cmd.Args = append(cmd.Args, "-u")
		cmd.Args = append(cmd.Args, mntDir)
		err := cmd.Run()
		if err != nil {
			logrus.Errorf("failed to unmount %s: %v", mntDir, err)
		}
		err = os.RemoveAll(layersRootDir)
		if err != nil {
			logrus.Errorf("failed to remove %s: %v", layersRootDir, err)
			return
		}
	}

	return mntDir, finalize, nil
}

func getImage(ctx context.Context, name string) (types.Image, error) {
	ref, err := alltransports.ParseImageName(name)
	if err != nil {
		return nil, err
	}
	imgSrc, err := ref.NewImageSource(ctx, &types.SystemContext{})
	if err != nil {
		return nil, err
	}

	imgRef := imgSrc.Reference().DockerReference()
	logrus.WithField("ref", imgRef).Info("[DEBUG]")

	refStr := imgRef.String()
	tagPos := strings.LastIndex(refStr, ":")
	repoPos := strings.Index(refStr, "/")

	repo := refStr[0:repoPos]
	imageName := refStr[repoPos+1 : tagPos]
	tag := refStr[tagPos+1 : len(refStr)]
	logrus.WithFields(logrus.Fields{
		"repo":  repo,
		"image": imageName,
		"tag":   tag,
	}).Info("[DEBUG]")

	img, err := image.FromUnparsedImage(ctx, nil, image.UnparsedInstance(imgSrc, nil))
	return img, err
}

func pullThread(ctx context.Context, idx int, pichan <-chan *pullInfo, wg *sync.WaitGroup) {
	logrus.WithField("thread", idx).Info("thread started")
	defer wg.Done()
	for {
		select {
		case pi, ok := <-pichan:
			if !ok {
				logrus.Error("channel error")
				return
			}
			logrus.WithField("layerInfo", pi.layerInfo).Infoln("pull layer")
			logrus.WithField("path", pi.layerInfo.path).Infoln("pull layer")
			err := pi.layerInfo.pullFunc()
			if err != nil {
				logrus.Errorf("error while pull: %+v", err)
				return
			}
			pi.Conn.Close()
		case <-ctx.Done():
			logrus.WithField("thread", idx).Info("thread finished")
			return
		}
	}
}

func waitRequest(ctx context.Context, conn net.Conn, pichan chan<- *pullInfo, wg *sync.WaitGroup, liMap map[string]*layerInfo) {
	defer wg.Done()
	buf := make([]byte, 128)
	logrus.Info("waiting")

	err := conn.SetReadDeadline(time.Now().Add(time.Millisecond * 500))
	if err != nil {
		logrus.Error("conn.SetReadDeadline: %+v")
	}

	var key string
	continue_read := true
	for continue_read {
		size, err := conn.Read(buf)
		switch {
		case err == nil:
			logrus.Infof("read data=%s", buf)
			key = string(buf[0:size])
			continue_read = false
		case os.IsTimeout(err):
			conn.SetReadDeadline(time.Now().Add(time.Millisecond * 500))
		case errors.Is(err, io.EOF):
			logrus.Errorf("read unexpected EOF: %+v", err)
		default:
			logrus.Errorf("read request error: %+v", err)
		}
		select {
		case <-ctx.Done():
			logrus.Infof("waitRequest canceled")
			return
		default:
		}
	}

	pi := &pullInfo{}
	pi.Conn = conn
	logrus.WithFields(
		logrus.Fields{
			"key": key,
			"len": len(key),
		}).Info("info")
	logrus.Info("get layer info")
	li, ok := liMap[key]
	if !ok {
		logrus.Error("error get layer info")
	}
	logrus.Info("select start")
	pi.layerInfo = li
	select {
	case pichan <- pi:
		logrus.Info("pi sent")
	case <-ctx.Done():
		logrus.Info("ctx.Done")
	}
	logrus.Info("select done")
}

func generateLayerPullFunc(url, dstRoot string, dgst *digest.Digest) func() error {
	var once sync.Once
	f := func() error {
		var err error = nil
		once.Do(func() {
			r, err := fetchBlobAsReader(url, dgst)
			if err != nil {
				return
			}
			err = untar(dstRoot, r)
		})
		return err
	}
	return f
}

func fetchBlobAsReader(url string, digest *digest.Digest) (io.ReadCloser, error) {

	req, err := http.NewRequest(http.MethodGet, url, nil)

	if err != nil {
		return nil, err
	}

	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		buf, err := httputil.DumpRequest(req, true)
		if err != nil {
			return nil, err
		}
		logrus.Debugf("%s", buf)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		buf, err := httputil.DumpResponse(res, true)
		if err != nil {
			return nil, err
		}
		if len(buf) > 100 {
			buf = buf[:100]
		}
		fmt.Fprintf(os.Stderr, "%s\n", buf)
	}

	if res.StatusCode/100 != 2 {
		return nil, xerrors.Errorf("status error of fetch blob: %s", res.Status)
	}
	return res.Body, nil
}

func untar(dstRootPath string, r io.Reader) error {
	logrus.WithField("root", dstRootPath).Info("untar")
	gzr, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gzr.Close()
	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		switch {
		case err == io.EOF:
			return nil
		case err != nil:
			return err
		case header == nil:
			continue
		}
		target := filepath.Join(dstRootPath, header.Name)
		// fi := header.FileInfo()
		switch header.Typeflag {
		case tar.TypeDir:
			if _, err := os.Stat(target); err != nil {
				if err := os.MkdirAll(target, 0755); err != nil {
					return err
				}
			}
		case tar.TypeReg:
			f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				return err
			}
			f.Close()
		}
	}
}
