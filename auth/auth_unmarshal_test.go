package auth_test

import (
	"net/http"
	"testing"

	auth "github.com/jonhadfield/gosn-v2/auth"
	"github.com/stretchr/testify/require"
)

func TestUnmarshalAuthRequestResponseOK(t *testing.T) {
	body := []byte(`{"data":{"identifier":"id","pw_salt":"salt","pw_cost":1,"pw_nonce":"nonce","version":"004"}}`)
	out, errResp, err := auth.UnmarshalAuthRequestResponseForTest(http.StatusOK, body, false)
	require.NoError(t, err)
	require.Equal(t, "id", out.Data.Identifier)
	require.Empty(t, errResp.Data.Error.Message)
}

func TestUnmarshalAuthRequestResponseNotFound(t *testing.T) {
	body := []byte(`{"meta":{},"data":{"error":{"tag":"invalid","message":"not found","payload":{"mfa_key":"abc"}}}}`)
	out, errResp, err := auth.UnmarshalAuthRequestResponseForTest(http.StatusNotFound, body, false)
	require.NoError(t, err)
	require.Equal(t, "abc", errResp.Data.Error.Payload.MFAKey)
	require.Empty(t, out.Data.Identifier)
}

func TestUnmarshalAuthRequestResponseForbidden(t *testing.T) {
	_, _, err := auth.UnmarshalAuthRequestResponseForTest(http.StatusForbidden, []byte(`{}`), false)
	require.Error(t, err)
}

func TestUnmarshalAuthRequestResponseBadRequestSurfacesAuthServiceError(t *testing.T) {
	body := []byte(`{"meta":{},"data":{"error":{"tag":"invalid-auth","message":"Invalid login credentials.","payload":{}}}}`)
	_, _, err := auth.UnmarshalAuthRequestResponseForTest(http.StatusBadRequest, body, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid login credentials.")
}

func TestUnmarshalAuthRequestResponseBadRequestSurfacesGatewayError(t *testing.T) {
	body := []byte(`{"error":{"message":"Your client version is no longer supported."}}`)
	_, _, err := auth.UnmarshalAuthRequestResponseForTest(http.StatusBadRequest, body, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Your client version is no longer supported.")
}

func TestUnmarshalAuthRequestResponseUnauthorizedSurfacesError(t *testing.T) {
	body := []byte(`{"meta":{},"data":{"error":{"tag":"unauthorized","message":"Please sign in.","payload":{}}}}`)
	_, _, err := auth.UnmarshalAuthRequestResponseForTest(http.StatusUnauthorized, body, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Please sign in.")
}

func TestUnmarshalAuthRequestResponseBadRequestMFAChallengeIsSoft(t *testing.T) {
	body := []byte(`{"meta":{},"data":{"error":{"tag":"mfa-required","message":"Please provide your MFA code.","payload":{"mfa_key":"mfa_12345"}}}}`)
	_, errResp, err := auth.UnmarshalAuthRequestResponseForTest(http.StatusBadRequest, body, false)
	require.NoError(t, err)
	require.Equal(t, "mfa_12345", errResp.Data.Error.Payload.MFAKey)
}

func TestUnmarshalAuthRequestResponseBadRequestUnparseableBody(t *testing.T) {
	body := []byte(`not even json`)
	_, _, err := auth.UnmarshalAuthRequestResponseForTest(http.StatusBadRequest, body, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not even json")
}
