package secrethub

import (
	"bytes"
	"fmt"

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
	sess, err := session.NewSession()
	if err != nil {
		return fmt.Errorf("could not get AWS session: %v", err)
	}

	region := endpoints.EuWest1RegionID
	svc := sts.New(sess, &aws.Config{
		Region: aws.String(region),
	})

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

	// TODO: this is obviously not finished
	//req := api.NewAuthRequestAWSSTS(api.SessionTypeHMAC, region, buf.Bytes())
	//resp, err := s.client.httpClient.AuthenticateHMAC(req)
	//if err != nil {
	//	return err
	//}
	//
	//client.
	return nil
}
