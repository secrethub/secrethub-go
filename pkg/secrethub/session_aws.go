package secrethub

import (
	"bytes"
	"fmt"

	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/internals/auth"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
)

const (
	// Currently always use the eu-west-1 region.
	defaultAWSRegionForSTS = endpoints.EuWest1RegionID
)

type awsSessionService struct {
	client    *client
	awsConfig []*aws.Config
}

func newAWSSessionService(client *client, awsCfg ...*aws.Config) SessionMethodService {
	return &awsSessionService{
		client:    client,
		awsConfig: awsCfg,
	}
}

func (s awsSessionService) Create() (auth.Authenticator, error) {
	region := defaultAWSRegionForSTS

	getCallerIdentityReq, err := getCallerIdentityRequest(region, s.awsConfig...)
	if err != nil {
		return nil, err
	}

	req := api.NewAuthRequestAWSSTS(api.SessionTypeHMAC, region, getCallerIdentityReq)
	resp, err := s.client.httpClient.Authenticate(req)
	if err != nil {
		return nil, err
	}
	if resp.Type != api.SessionTypeHMAC {
		return nil, api.ErrInvalidSessionType
	}
	hmacSession := resp.HMAC()

	return auth.NewHTTPSigner(auth.NewSessionSigner(hmacSession.SessionID, hmacSession.Payload.SessionKey)), nil
}

// getCallerIdentityRequest returns the raw bytes of a signed GetCallerIdentity request.
func getCallerIdentityRequest(region string, awsCfg ...*aws.Config) ([]byte, error) {
	cfg := aws.NewConfig().WithRegion(region).WithEndpoint("sts." + region + ".amazonaws.com")
	awsSession, err := session.NewSession(append(awsCfg, cfg)...)
	if err != nil {
		return nil, fmt.Errorf("could not get AWS session: %v", err)
	}

	svc := sts.New(awsSession, cfg)
	stsReq, _ := svc.GetCallerIdentityRequest(&sts.GetCallerIdentityInput{})

	err = stsReq.Sign()
	if err != nil {
		return nil, fmt.Errorf("could not sign STS request: %v", err)
	}

	var buf bytes.Buffer
	err = stsReq.HTTPRequest.Write(&buf)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
