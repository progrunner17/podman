package containers

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strconv"
	"strings"
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
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	spec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/sys/unix"
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
	var name string
	if !cliVals.RootFS {
		name, ociCfg, err = pullRImage(args[0])
		// 		name, err := pullImage(args[0])
		if err != nil {
			return err
		}
		imageName = name
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
	ctrMntDir, ctrRootDir, err := createRootFSMountPoint(imageName)
	if err != nil {
		return err
	}
	defer finalizeMountPoint(ctrMntDir, ctrRootDir)
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
	logrus.WithField("imageRef", imageRef).Info("[DEBUG]")
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
	// 各種設定
	cmd.Args = append(cmd.Args, "-d")
	cmd.Args = append(cmd.Args, "--debug")

	opts := "-o"
	opts += fmt.Sprintf("remote_image=%s,", image)
	opts += fmt.Sprintf("workdir=%s,", workDir)
	opts += fmt.Sprintf("upperdir=%s,", upperDir)
	opts += "src_type=remote"
	cmd.Args = append(cmd.Args, opts)
	cmd.Args = append(cmd.Args, mntDir)
	err = cmd.Start()
	if err != nil {
		return "", rootDir, fmt.Errorf("failed to execute llpfs: %v", err)
	}
	time.Sleep(time.Millisecond * 5000)
	return mntDir, rootDir, nil
}

func finalizeMountPoint(mntPoint, rootDir string) error {
	err := unix.Unmount(mntPoint, 0)
	if err != nil {
		logrus.Errorf("failed to unmount %s: %v", mntPoint, err)
		return err
	}
	err = os.RemoveAll(rootDir)
	if err != nil {
		logrus.Errorf("failed to remove %s: %v", mntPoint, err)
		return err
	}
	return nil
}
