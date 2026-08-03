package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/kciceblue/sshserver/runtime/internal/buildinfo"
	"github.com/kciceblue/sshserver/runtime/internal/deployment"
	"github.com/kciceblue/sshserver/runtime/internal/releasebundle"
)

func main() {
	syscall.Umask(0o077)
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	if err := execute(args, stdout, stderr); err != nil {
		fmt.Fprintf(stderr, "releasebundle: %v\n", err)
		return 1
	}
	return 0
}

func execute(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("requires identity, attestation, or generate")
	}
	switch args[0] {
	case "identity":
		return runIdentity(args[1:], stdout, stderr)
	case "attestation":
		return runAttestation(args[1:], stdout, stderr)
	case "generate":
		return runGenerate(args[1:], stdout, stderr)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

type identityOptions struct {
	release         string
	sourceRevision  string
	buildToolchain  string
	operatingSystem string
	architecture    string
}

func addIdentityFlags(flags *flag.FlagSet, options *identityOptions) {
	flags.StringVar(&options.release, "release", "", "immutable release identifier")
	flags.StringVar(&options.sourceRevision, "source-revision", "", "exact lowercase Git commit ID")
	flags.StringVar(&options.buildToolchain, "build-toolchain", "", "exact Go patch release")
	flags.StringVar(&options.operatingSystem, "os", "", "release target operating system")
	flags.StringVar(&options.architecture, "architecture", "", "release target architecture")
}

func deriveIdentity(options identityOptions) (string, error) {
	return deployment.DeriveBuildIdentity(options.release, options.sourceRevision, options.buildToolchain, deployment.Target{
		OS: options.operatingSystem, Architecture: options.architecture,
	})
}

func runIdentity(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("identity", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var options identityOptions
	addIdentityFlags(flags, &options)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("identity accepts no positional arguments")
	}
	identity, err := deriveIdentity(options)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, identity)
	return err
}

func runAttestation(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("attestation", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var options identityOptions
	addIdentityFlags(flags, &options)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("attestation accepts no positional arguments")
	}
	identity, err := deriveIdentity(options)
	if err != nil {
		return err
	}
	encoded, err := buildinfo.Encode(buildinfo.Identity{
		Release:         options.release,
		SourceRevision:  options.sourceRevision,
		BuildToolchain:  options.buildToolchain,
		BuildIdentity:   identity,
		ProtocolVersion: "1",
		StorageSchema:   "1",
	})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, encoded)
	return err
}

func runGenerate(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("generate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var options releasebundle.Options
	flags.StringVar(&options.ArtifactDir, "artifacts", "", "canonical absolute verified build-artifact directory")
	flags.StringVar(&options.DistDir, "dist", "", "canonical absolute distribution directory")
	flags.StringVar(&options.LicensePath, "license", "", "canonical absolute Apache-2.0 LICENSE source")
	flags.StringVar(&options.NoticePath, "notice", "", "canonical absolute NOTICE source")
	flags.StringVar(&options.Release, "release", "", "immutable release identifier")
	flags.StringVar(&options.SourceRevision, "source-revision", "", "exact lowercase Git commit ID")
	flags.StringVar(&options.BuildToolchain, "build-toolchain", "", "exact Go patch release")
	flags.StringVar(&options.DownloadOrigin, "download-origin", "", "exact direct HTTPS download origin")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("generate accepts no positional arguments")
	}
	result, err := releasebundle.Generate(options)
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(result)
}
