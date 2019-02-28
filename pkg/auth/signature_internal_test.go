package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"net/http"

	"bytes"

	"io/ioutil"

	"github.com/keylockerbv/secrethub-go/internals/assert"
)

func TestGetMessage_Get(t *testing.T) {

	// Arrange
	req, err := http.NewRequest("GET", "https://api.secrethub.io/repos/jdoe/catpictures", nil)
	assert.OK(t, err)
	req.Header.Set("Date", "Fri, 10 Mar 2017 16:25:54 CET")

	expected := "GET\n" +
		"\n" +
		"Fri, 10 Mar 2017 16:25:54 CET\n" +
		"/repos/jdoe/catpictures;"

	// Act
	result, err := getMessage(req)
	assert.OK(t, err)

	// Assert
	assertMessage(t, expected, string(result))
}

func TestGetMessage_Post(t *testing.T) {

	// Assert
	body := bytes.NewBufferString("GRUMBYCAT")

	req, err := http.NewRequest("POST", "https://api.secrethub.io/repos/jdoe/catpictures", body)
	assert.OK(t, err)
	req.Header.Set("Date", "Fri, 10 Mar 2017 16:25:54 CET")

	bodySum := sha256.Sum256(body.Bytes())
	encodedBody := base64.StdEncoding.EncodeToString(bodySum[:])

	expected := "POST\n" +
		encodedBody + "\n" +
		"Fri, 10 Mar 2017 16:25:54 CET\n" +
		"/repos/jdoe/catpictures;\n" +
		""

	// Act
	result, err := getMessage(req)
	assert.OK(t, err)

	// Assert
	assertMessage(t, expected, string(result))
}

func assertMessage(t *testing.T, expected, result string) {

	resultPayload := strings.Split(result, ";")
	resultSplits := strings.Split(resultPayload[0], "\n")

	expectedPayload := strings.Split(expected, ";")
	expectedSplits := strings.Split(expectedPayload[0], "\n")

	if len(resultSplits) != 4 {
		t.Errorf("Payload not correct number of lines.")
	}

	// Method
	if resultSplits[0] != expectedSplits[0] {
		t.Errorf("method not in payload correctly.\n Expected:\n%s\n Actual: \n%s\n", expectedSplits[0], resultSplits[0])
	}

	if resultSplits[1] != expectedSplits[1] {
		t.Errorf("content-hash not in payload correctly.\n Expected:\n%s\n Actual: \n%s\n", expectedSplits[1], resultSplits[1])
	}

	_, err := time.Parse(time.RFC1123, expectedSplits[2])
	// Time
	if err != nil {
		t.Error(err)
	}
	// Resource
	if resultSplits[3] != expectedSplits[3] {
		t.Errorf("resource not in payload correctly.\n Expected:\n%s\n Actual: \n%s\n", expectedSplits[3], resultSplits[3])
	}
}

// ContentLength should still equal the body length
func TestGetPayloadToSign_ContentLength(t *testing.T) {

	// Assert
	requestBody := bytes.NewBufferString("GRUMBYCAT")

	req, err := http.NewRequest("POST", "https://api.secrethub.io/repos/jdoe/catpictures", requestBody)
	assert.OK(t, err)
	req.Header.Set("Date", "Fri, 10 Mar 2017 16:25:54 CET")

	// Act
	_, err = getMessage(req)
	assert.OK(t, err)

	// Assert
	body, err := ioutil.ReadAll(req.Body)
	assert.OK(t, err)

	if len(body) != int(req.ContentLength) {
		t.Fatal("Content-Length should equal body length.")
	}
}

func TestIsTimeValid(t *testing.T) {

	// Arrange
	now := time.Now().UTC().Round(time.Second)
	berlin, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Fatal(err)
	}

	// Daylight savings
	form := "2006-01-02 15:04"
	startDST, err := time.ParseInLocation(form, "2017-03-26 02:00", berlin)
	if err != nil {
		t.Fatal(err)
	}
	endDST, err := time.ParseInLocation(form, "2017-10-29 03:00", berlin)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		descr    string
		client   time.Time
		server   time.Time
		expected error
	}{
		{
			descr:    "on point for requests from the past",
			client:   now,
			server:   now.Add(maxExpirationDifference),
			expected: nil,
		},
		{
			descr:    "off point for requests from the past",
			client:   now,
			server:   now.Add(maxExpirationDifference + time.Second),
			expected: ErrSignatureExpired,
		},
		{
			descr:    "on point for requests from the future",
			client:   now.Add(maxClockSkew),
			server:   now,
			expected: nil,
		},
		{
			descr:    "off point for requests from the future",
			client:   now.Add(maxClockSkew + time.Second),
			server:   now,
			expected: ErrSignatureFuture,
		},
		{
			descr:    "client one timezone behind",
			client:   now.In(time.FixedZone("behind", -3600)),
			server:   now,
			expected: nil,
		},
		{
			descr:    "client one time zone forward",
			client:   now.In(time.FixedZone("forward", 3600)),
			server:   now,
			expected: nil,
		},
		{
			descr:    "client not yet in daylight savings",
			client:   startDST.Add(-2 * time.Second),
			server:   startDST.Add(2 * time.Second),
			expected: nil,
		},
		{
			descr:    "client already in daylight savings",
			client:   startDST.Add(2 * time.Second),
			server:   startDST.Add(-2 * time.Second),
			expected: nil,
		},
		{
			descr:    "client not yet out of daylight savings",
			client:   endDST.Add(-2 * time.Second),
			server:   endDST.Add(2 * time.Second),
			expected: nil,
		},
		{
			descr:    "client already out of daylight savings",
			client:   endDST.Add(2 * time.Second),
			server:   endDST.Add(-2 * time.Second),
			expected: nil,
		},
	}

	for _, test := range tests {
		// Act
		err = isTimeValid(test.client, test.server)

		// Assert
		if err != test.expected {
			t.Logf("%s:\n\t%s (client)\n\t%s (server)", test.descr, test.client, test.server)
			t.Errorf("unexpected error: %v (actual) != %v (expected)", err, test.expected)
		}
	}
}
