package sessions

import (
	"bytes"

	"github.com/aws/aws-sdk-go/aws/awserr"
	shaws "github.com/secrethub/secrethub-go/internals/aws"
	"github.com/secrethub/secrethub-go/internals/errio"

	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/pkg/secrethub/internals/http"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
)

const (
	// Currently always use the eu-west-1 region.
	defaultAWSRegionForSTS = endpoints.EuWest1RegionID
)

type awsSessionCreator struct {
	awsConfig []*aws.Config
}

// NewAWSSessionCreator returns a SessionCreator that uses AWS STS authentication to request sessions.
func NewAWSSessionCreator(awsCfg ...*aws.Config) SessionCreator {
	return &awsSessionCreator{
		awsConfig: awsCfg,
	}
}

// Create a new Session using AWS STS for authentication.
func (s *awsSessionCreator) Create(httpClient *http.Client) (Session, error) {
	region := defaultAWSRegionForSTS

	getCallerIdentityReq, err := getCallerIdentityRequest(region, s.awsConfig...)
	if err != nil {
		return nil, handleAWSErr(err)
	}

	req := api.NewAuthRequestAWSSTS(api.SessionTypeHMAC, region, getCallerIdentityReq)
	resp, err := httpClient.CreateSession(req)
	if err != nil {
		return nil, handleAWSErr(err)
	}
	if resp.Type != api.SessionTypeHMAC {
		return nil, api.ErrInvalidSessionType
	}
	sess := resp.HMAC()

	return &hmacSession{
		sessionID:  sess.SessionID,
		sessionKey: sess.Payload.SessionKey,
		expireTime: expireTime(sess.Expires),
	}, nil
}

// getCallerIdentityRequest returns the raw bytes of a signed GetCallerIdentity request.
func getCallerIdentityRequest(region string, awsCfg ...*aws.Config) ([]byte, error) {
	// Explicitly set the endpoint because the aws sdk by default uses the global endpoint.
	cfg := aws.NewConfig().WithRegion(region).WithEndpoint("sts." + region + ".amazonaws.com")
	awsSession, err := session.NewSession(append(awsCfg, cfg)...)
	if err != nil {
		return nil, err
	}

	svc := sts.New(awsSession, cfg)
	identityRequest, _ := svc.GetCallerIdentityRequest(&sts.GetCallerIdentityInput{})

	// Sign the CallerIdentityRequest with the AWS access key
	err = identityRequest.Sign()
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	err = identityRequest.HTTPRequest.Write(&buf)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func handleAWSErr(err error) error {
	errAWS, ok := err.(awserr.Error)
	if ok {
		if errAWS.Code() == "NoCredentialProviders" {
			return shaws.ErrNoAWSCredentials
		}
		err = errio.Namespace("aws").Code(errAWS.Code()).Error(errAWS.Message())
	}
	return err
}
