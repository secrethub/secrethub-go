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

type awsAuthService struct {
	client client
}

func newAWSAuthService(client client) AuthMethodService {
	return &awsAuthService{
		client: client,
	}
}

func (s awsAuthService) Authenticate() error {
	region := endpoints.EuWest1RegionID
	cfg := aws.NewConfig().WithRegion(region).WithEndpoint("sts." + region + ".amazonaws.com")
	awsSess, err := session.NewSession(cfg)
	if err != nil {
		return fmt.Errorf("could not get AWS session: %v", err)
	}

	svc := sts.New(awsSess, cfg)

	stsReq, _ := svc.GetCallerIdentityRequest(&sts.GetCallerIdentityInput{})

	err = stsReq.Sign()
	if err != nil {
		return fmt.Errorf("could not sign STS request: %v", err)
	}

	var buf bytes.Buffer
	err = stsReq.HTTPRequest.Write(&buf)
	if err != nil {
		return err
	}

	req := api.NewAuthRequestAWSSTS(api.SessionTypeHMAC, region, buf.Bytes())
	resp, err := s.client.httpClient.Authenticate(req)
	if err != nil {
		return err
	}
	if *resp.Type != api.SessionTypeHMAC {
		return api.ErrInvalidSessionType
	}
	sess := resp.HMAC()
	s.client.httpClient.authenticator = auth.NewHTTPSigner(auth.NewSessionSigner(sess.SessionID, api.StringValue(sess.Payload.SecretKey)))

	return nil
}
