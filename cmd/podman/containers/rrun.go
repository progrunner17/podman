package containers

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/containers/common/pkg/config"
	"github.com/containers/image/v5/storage"
	"github.com/containers/image/v5/transports/alltransports"
	"github.com/containers/libpod/v2/cmd/podman/common"
	"github.com/containers/libpod/v2/cmd/podman/registry"
	"github.com/containers/libpod/v2/libpod/define"
	"github.com/containers/libpod/v2/libpod/events"
	"github.com/containers/libpod/v2/pkg/domain/entities"
	"github.com/containers/libpod/v2/pkg/domain/infra/abi"
	"github.com/containers/libpod/v2/pkg/domain/infra/abi/terminal"
	"github.com/containers/libpod/v2/pkg/errorhandling"
	"github.com/containers/libpod/v2/pkg/rootless"
	"github.com/containers/libpod/v2/pkg/specgen"
	"github.com/containers/libpod/v2/pkg/specgen/generate"
	"github.com/containers/libpod/v2/pkg/util"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
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
	if !cliVals.RootFS {
		name, err := pullRImage(args[0])
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
	s := specgen.NewSpecGenerator(imageName, cliVals.RootFS)
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

func pullRImage(imageName string) (string, error) {
	pullPolicy, err := config.ValidatePullPolicy(cliVals.Pull)
	if err != nil {
		return "", err
	}

	// Check if the image is missing and hence if we need to pull it.
	imageMissing := true
	imageRef, err := alltransports.ParseImageName(imageName)
	switch {
	case err != nil:
		// Assume we specified a local image withouth the explicit storage transport.
		fallthrough

	case imageRef.Transport().Name() == storage.Transport.Name():
		br, err := registry.ImageEngine().Exists(registry.GetContext(), imageName)
		if err != nil {
			return "", err
		}
		imageMissing = !br.Value
	}

	if imageMissing || pullPolicy == config.PullImageAlways {
		if pullPolicy == config.PullImageNever {
			return "", errors.Wrapf(define.ErrNoSuchImage, "unable to find a name and tag match for %s in repotags", imageName)
		}
		pullReport, pullErr := registry.ImageEngine().Pull(registry.GetContext(), imageName, entities.ImagePullOptions{
			Authfile:     cliVals.Authfile,
			Quiet:        cliVals.Quiet,
			OverrideArch: cliVals.OverrideArch,
			OverrideOS:   cliVals.OverrideOS,
		})
		if pullErr != nil {
			return "", pullErr
		}
		imageName = pullReport.Images[0]
	}
	return imageName, nil
}

// [TODO]: manifestやconfigをこの関数に渡したい
func containerRRun(ctx context.Context, raw_ic entities.ContainerEngine, opts entities.ContainerRunOptions) (*entities.ContainerRunReport, error) {
	ic, ok := raw_ic.(*abi.ContainerEngine)
	if !ok {
		return nil, fmt.Errorf("ContainerEngine needs abi.ContainerEngine")
	}

	// [TODO]: remote imageを使うように変更
	warn, err := generate.CompleteSpec(ctx, ic.Libpod, opts.Spec)
	if err != nil {
		return nil, err
	}
	// Print warnings
	for _, w := range warn {
		fmt.Fprintf(os.Stderr, "%s\n", w)
	}
	// [TODO]: remote imageを使うように変更
	ctr, err := generate.MakeContainer(ctx, ic.Libpod, opts.Spec)
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
