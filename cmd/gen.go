package cmd

import (
	"fmt"
	"github.com/99designs/keyring"
	"github.com/hunkeelin/aws-okta/lib"
	analytics "github.com/segmentio/analytics-go"
	"github.com/spf13/cobra"
	"os"
	"os/user"
)

// genCmd represents the gen command
var genCmd = &cobra.Command{
	Use:    "gen <profile>",
	Short:  "gen will generate aws config for you",
	RunE:   genRun,
	PreRun: genPre,
}

var filedir string
var all bool

func init() {
	RootCmd.AddCommand(genCmd)
	genCmd.Flags().StringVarP(&filedir, "path", "p", "", "The file path you want the credentials to be generated on")
	genCmd.Flags().BoolVarP(&all, "genall", "", false, "Select this option if you want to generate credentials for all roles.")
}
func genPre(cmd *cobra.Command, args []string) {
	if filedir == "" {
		u, err := user.Current()
		if err != nil {
			return err
		}
		filedir = "/User/" + u.Username + "/.aws/credentials"
	}
}
func genRun(cmd *cobra.Command, args []string) error {
	var towrite []byte
	if len(args) < 1 {
		return ErrTooFewArguments
	}
	if len(args) > 1 {
		return ErrTooManyArguments
	}
	profile := args[0]
	config, err := lib.NewConfigFromEnv()
	if err != nil {
		return err
	}

	profiles, err := config.Parse()
	if err != nil {
		return err
	}

	prof, ok := profiles[profile]
	if !ok {
		return fmt.Errorf("Profile '%s' not found in your aws config", profile)
	}
	updateMfaConfig(cmd, profiles, profile, &mfaConfig)
	opts := lib.ProviderOptions{
		MFAConfig:          mfaConfig,
		Profiles:           profiles,
		SessionDuration:    sessionTTL,
		AssumeRoleDuration: assumeRoleTTL,
	}
	var allowedBackends []keyring.BackendType
	if backend != "" {
		allowedBackends = append(allowedBackends, keyring.BackendType(backend))
	}
	kr, err := lib.OpenKeyring(allowedBackends)
	if err != nil {
		return err
	}
	if analyticsEnabled && analyticsClient != nil {
		analyticsClient.Enqueue(analytics.Track{
			UserId: username,
			Event:  "Ran Command",
			Properties: analytics.NewProperties().
				Set("backend", backend).
				Set("aws-okta-version", version).
				Set("profile", profile).
				Set("command", "login"),
		})
	}
	p, err := lib.NewProvider(kr, profile, opts)
	if err != nil {
		return err
	}

	if _, ok := prof["aws_saml_url"]; ok {
		err = oktaLogin(p)
		if err != nil {
			return fmt.Errorf("Unable to execute okta login %v", err)
		}
	} else {
		if all {
			for key, _ := range profiles {
				w, err = generateCredFile(p, profile, profiles)
				if err != nil {
					return fmt.Errorf("Unable to generate cred file %v", err)
				}
				towrite = append(towrite, w...)
			}
		} else {
			towrite, err = generateCredFile(p, profile, profiles)
			if err != nil {
				return fmt.Errorf("Unable to generate cred file %v", err)
			}
		}
		f, err := os.OpenFile(filedir, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|os.O_APPEND, 0600)
		if err != nil {
			return err
		}
		defer f.Close()
		f.Write(towrite)
	}
	return nil
}

func generateCredFile(p *lib.Provider, profile string, profiles lib.Profiles) error {
	var toreturn []byte
	creds, err := p.Retrieve()
	if err != nil {
		return toreturn, err
	}
	l0 := []byte("[" + profile + "]\n")
	l1 := []byte("aws_access_key_id = " + creds.AccessKeyID + "\n")
	l2 := []byte("aws_secret_access_key = " + creds.SecretAccessKey + "\n")
	l3 := []byte("aws_session_token = " + creds.SessionToken + "\n")
	toreturn = append(toreturn, l0...)
	toreturn = append(toreturn, l1...)
	toreturn = append(toreturn, l2...)
	toreturn = append(toreturn, l3...)
	return toreturn, nil
}
