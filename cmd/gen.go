package cmd

import (
	//"encoding/json"
	"fmt"
//	"io/ioutil"
//	"net/http"
//	"net/url"
	"os"
//	"time"

	"github.com/99designs/keyring"
	analytics "github.com/segmentio/analytics-go"
	"github.com/hunkeelin/aws-okta/lib"
//	"github.com/skratchdot/open-golang/open"
	"github.com/spf13/cobra"
)

// genCmd represents the gen command
var genCmd = &cobra.Command{
	Use:    "gen <profile>",
    Short: "gen will generate aws config for you",
	RunE:   genRun,
//	PreRun: genPre,
}

// Stdout is the bool for -stdout

var filedir string
func init() {
	RootCmd.AddCommand(genCmd)
	genCmd.Flags().StringVarP(&filedir,"path", "p", "~/.aws/credentials", "The file path you want the credentials to be generated on")
}

func genRun(cmd *cobra.Command, args []string) error {
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
            return fmt.Errorf("Unable to execute okta login %v",err)
        }
    } else {
        err  = generateCredFile(p,profile , profiles)
        if err != nil {
            return fmt.Errorf("Unable to generate cred file %v",err)
        }
    }
    return nil
}

func generateCredFile(p *lib.Provider, profile string, profiles lib.Profiles) error {
	creds, err := p.Retrieve()
	if err != nil {
		return err
	}
    f,err := os.OpenFile(filedir,os.O_WRONLY|os.O_CREATE|os.O_TRUNC|os.O_APPEND,0600)
    if err != nil {
        return err
    }
    l0 := []byte("["+profile+"]\n")
    l1 := []byte("aws_access_key_id = "+creds.AccessKeyID+"\n")
    l2 := []byte("aws_secret_access_key = "+creds.SecretAccessKey+"\n")
    l3 := []byte("aws_session_token = "+creds.SessionToken+"\n")
    var towrite []byte
    towrite = append(towrite,l0...)
    towrite = append(towrite,l1...)
    towrite = append(towrite,l2...)
    towrite = append(towrite,l3...)
    f.Write(towrite)
    f.Close()
    return nil
}
