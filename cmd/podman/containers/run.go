package containers

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/containers/common/pkg/completion"
	"github.com/containers/podman/v2/cmd/podman/common"
	"github.com/containers/podman/v2/cmd/podman/registry"
	"github.com/containers/podman/v2/cmd/podman/utils"
	"github.com/containers/podman/v2/libpod/define"
	"github.com/containers/podman/v2/pkg/domain/entities"
	"github.com/containers/podman/v2/pkg/errorhandling"
	"github.com/containers/podman/v2/pkg/rootless"
	"github.com/containers/podman/v2/pkg/specgen"
	"github.com/containers/podman/v2/pkg/util"
	"github.com/pkg/errors"
	llpfslib "github.com/progrunner17/llpfsutil/lib"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	runDescription = "Runs a command in a new container from the given image"
	runCommand     = &cobra.Command{
		Args:              cobra.MinimumNArgs(1),
		Use:               "run [options] IMAGE [COMMAND [ARG...]]",
		Short:             "Run a command in a new container",
		Long:              runDescription,
		RunE:              run,
		ValidArgsFunction: common.AutocompleteCreateRun,
		Example: `podman run imageID ls -alF /etc
  podman run --network=host imageID dnf -y install java
  podman run --volume /var/hostdir:/var/ctrdir -i -t fedora /bin/bash`,
	}

	containerRunCommand = &cobra.Command{
		Args:              cobra.MinimumNArgs(1),
		Use:               runCommand.Use,
		Short:             runCommand.Short,
		Long:              runCommand.Long,
		RunE:              runCommand.RunE,
		ValidArgsFunction: runCommand.ValidArgsFunction,
		Example: `podman container run imageID ls -alF /etc
	podman container run --network=host imageID dnf -y install java
	podman container run --volume /var/hostdir:/var/ctrdir -i -t fedora /bin/bash`,
	}
)

var (
	runOpts = entities.ContainerRunOptions{
		OutputStream: os.Stdout,
		InputStream:  os.Stdin,
		ErrorStream:  os.Stderr,
	}
	runRmi bool
)

func runFlags(cmd *cobra.Command) {
	flags := cmd.Flags()

	flags.SetInterspersed(false)
	common.DefineCreateFlags(cmd, &cliVals)
	common.DefineNetFlags(cmd)

	flags.SetNormalizeFunc(utils.AliasFlags)
	flags.BoolVar(&runOpts.SigProxy, "sig-proxy", true, "Proxy received signals to the process")
	flags.BoolVar(&runRmi, "rmi", false, "Remove container image unless used by other containers")

	preserveFdsFlagName := "preserve-fds"
	flags.UintVar(&runOpts.PreserveFDs, "preserve-fds", 0, "Pass a number of additional file descriptors into the container")
	_ = cmd.RegisterFlagCompletionFunc(preserveFdsFlagName, completion.AutocompleteNone)

	flags.BoolVarP(&runOpts.Detach, "detach", "d", false, "Run container in background and print container ID")

	detachKeysFlagName := "detach-keys"
	flags.StringVar(&runOpts.DetachKeys, detachKeysFlagName, containerConfig.DetachKeys(), "Override the key sequence for detaching a container. Format is a single character `[a-Z]` or a comma separated sequence of `ctrl-<value>`, where `<value>` is one of: `a-cf`, `@`, `^`, `[`, `\\`, `]`, `^` or `_`")
	_ = cmd.RegisterFlagCompletionFunc(detachKeysFlagName, common.AutocompleteDetachKeys)

	_ = flags.MarkHidden("signature-policy")
	if registry.IsRemote() {
		_ = flags.MarkHidden("http-proxy")
		_ = flags.MarkHidden("preserve-fds")
	}
}
func init() {
	registry.Commands = append(registry.Commands, registry.CliCommand{
		Mode:    []entities.EngineMode{entities.ABIMode, entities.TunnelMode},
		Command: runCommand,
	})

	runFlags(runCommand)

	registry.Commands = append(registry.Commands, registry.CliCommand{
		Mode:    []entities.EngineMode{entities.ABIMode, entities.TunnelMode},
		Command: containerRunCommand,
		Parent:  containerCmd,
	})

	runFlags(containerRunCommand)
}

func run(cmd *cobra.Command, args []string) error {
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
			return err
		}
	}

	runOpts.CIDFile = cliVals.CIDFile
	runOpts.Rm = cliVals.Rm
	if err := createInit(cmd); err != nil {
		return err
	}
	for fd := 3; fd < int(3+runOpts.PreserveFDs); fd++ {
		if !rootless.IsFdInherited(fd) {
			return errors.Errorf("file descriptor %d is not available - the preserve-fds option requires that file descriptors must be passed", fd)
		}
	}

	imageName := args[0]
	rawImageName := ""
	cliVals.RootFS = true
	if !cliVals.RootFS {
		rawImageName = args[0]
		name, err := pullImage(args[0])
		if err != nil {
			return err
		}
		imageName = name
	}
	ctx := registry.GetContext()
	ctx, cancel := context.WithCancel(ctx)

	img, err := llpfslib.GetImageFromName(ctx, imageName)
	if err != nil {
		return err
	}
	asyncStr, ok := os.LookupEnv("PODMAN_LAZY_PULL_ASYNC")
	async := ok && asyncStr != "" && asyncStr != "0" && asyncStr != "false"
	numThreadsStr, ok := os.LookupEnv("PODMAN_LAZY_PULL_THREADS")
	numThreads, err := strconv.Atoi(numThreadsStr)
	if err != nil || !ok {
		numThreads = 1
	}
	llpfslib.SetMaxNumThread(numThreads)
	mntDir, finalize, err := llpfslib.MountImageAsRemoteOnTmp(ctx, img, async)
	if err != nil {
		return err
	}
	defer finalize()
	defer cancel()
	imageName = mntDir

	if cliVals.Replace {
		if err := replaceContainer(cliVals.Name); err != nil {
			return err
		}
	}

	// If -i is not set, clear stdin
	if !cliVals.Interactive {
		runOpts.InputStream = nil
	}

	// If attach is set, clear stdin/stdout/stderr and only attach requested
	if cmd.Flag("attach").Changed {
		runOpts.OutputStream = nil
		runOpts.ErrorStream = nil
		if !cliVals.Interactive {
			runOpts.InputStream = nil
		}

		for _, stream := range cliVals.Attach {
			switch strings.ToLower(stream) {
			case "stdout":
				runOpts.OutputStream = os.Stdout
			case "stderr":
				runOpts.ErrorStream = os.Stderr
			case "stdin":
				runOpts.InputStream = os.Stdin
			default:
				return errors.Wrapf(define.ErrInvalidArg, "invalid stream %q for --attach - must be one of stdin, stdout, or stderr", stream)
			}
		}
	}
	cliVals.PreserveFDs = runOpts.PreserveFDs
	s := specgen.NewSpecGenerator(imageName, cliVals.RootFS)
	ociCfg, err := img.OCIConfig(ctx)
	if err != nil {
		return err
	}
	s.Rootfs = mntDir
	logrus.WithField("Rootfs", s.Rootfs).Info("[DEBUG]")

	if len(args) == 1 {
		args = append(args, ociCfg.Config.Cmd...)
	}
	// 	logrus.WithField("command", os.Args).Info("[DEBUG]")
	if cliVals.User == "" {
		cliVals.User = ociCfg.Config.User
	}
	// 	if cliVals.Entrypoint == nil {
	// 		cliVals.Entrypoint = ociCfg.Config.Entrypoint
	// 	}
	if cliVals.Workdir == "" {
		cliVals.Workdir = ociCfg.Config.WorkingDir
	}
	cliVals.Env = append(ociCfg.Config.Env, cliVals.Env...)

	if err := common.FillOutSpecGen(s, &cliVals, args); err != nil {
		return err
	}
	logrus.WithField("workdir", s.WorkDir).Info("[DEBUG]")
	logrus.WithField("user", s.User).Info("[DEBUG]")
	logrus.WithField("env", s.Env).Info("[DEBUG]")
	logrus.WithField("command2", s.Command).Info("[DEBUG]")
	s.Entrypoint = ociCfg.Config.Entrypoint
	logrus.WithField("entrypoint", s.Entrypoint).Info("[DEBUG]")
	s.RawImageName = rawImageName
	runOpts.Spec = s

	if _, err := createPodIfNecessary(s, cliVals.Net); err != nil {
		return err
	}

	report, err := registry.ContainerEngine().ContainerRun(registry.GetContext(), runOpts)
	// report.ExitCode is set by ContainerRun even it it returns an error
	if report != nil {
		registry.SetExitCode(report.ExitCode)
	}
	if err != nil {
		return err
	}

	if runOpts.Detach {
		fmt.Println(report.Id)
		return nil
	}
	if runRmi {
		_, rmErrors := registry.ImageEngine().Remove(registry.GetContext(), []string{imageName}, entities.ImageRemoveOptions{})
		if len(rmErrors) > 0 {
			logrus.Errorf("%s", errorhandling.JoinErrors(rmErrors))
		}
	}
	return nil
}
