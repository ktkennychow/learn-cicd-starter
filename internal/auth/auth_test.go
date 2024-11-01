package auth

import (
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	type test struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
	}
	tests := []test{
		{
			name:          "No authorization header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed header - invalid authouization header",
			headers: http.Header{
				"Authorization": []string{"KApiKey 43fds342"},
			},
			expectedKey:   "",
			expectedError: ErrMalformedAuthHeader,
		},
		{
			name: "Valid API key",
			headers: http.Header{
				"Authorization": []string{"ApiKey xyz123"},
			},
			expectedKey:   "xyz123",
			expectedError: nil,
		},
	}
	t.Log("Testing Auth")
	numOfTests := len(tests)
	failedTests := 0
	for _, test := range tests {
		testName := fmt.Sprintf("Testing %v", test.name)
		t.Run(testName, func(t *testing.T) {
			testFailed := false
			key, err := GetAPIKey(test.headers)
			expectedKey := test.expectedKey
			expectedErr := test.expectedError
			if !reflect.DeepEqual(expectedKey, key) {
				testFailed = true
				t.Errorf("expect key: %v, got: %v", expectedKey, key)
			}
			if !errors.Is(expectedErr, err) {
				testFailed = true
				t.Errorf("expect error: %v, got: %v", expectedErr, err)
			}
			if testFailed {
				failedTests++
			}
		})
	}

	t.Log("All tests done")
	if failedTests == 0 {
		t.Log("All tests passed")
	} else {
		t.Logf("%v of %v test(s) failed", failedTests, numOfTests)
	}
}
