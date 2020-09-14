package containers

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/containers/libpod/v2/cmd/podman/common"
	"github.com/containers/libpod/v2/cmd/podman/registry"
	"github.com/containers/libpod/v2/libpod/define"
	"github.com/containers/libpod/v2/pkg/domain/entities"
	"github.com/containers/libpod/v2/pkg/errorhandling"
	"github.com/containers/libpod/v2/pkg/rootless"
	"github.com/containers/libpod/v2/pkg/specgen"
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
		name, err := pullImage(args[0])
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

	//[TODO]: ContainerRRunを作る
	report, err := registry.ContainerEngine().ContainerRun(registry.GetContext(), rrunOpts)
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
