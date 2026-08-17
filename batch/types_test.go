package batch

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRFC3339_MarshalJSON(t *testing.T) {
	ts := time.Date(2025, 3, 15, 10, 30, 45, 123456789, time.UTC)
	rfc := RFC3339{T: ts}

	data, err := json.Marshal(rfc)
	assert.NoError(t, err)
	assert.Contains(t, string(data), "2025-03-15T10:30:45Z")
	assert.NotContains(t, string(data), "123456789", "nanosecond part should be truncated")
}

func TestRFC3339_MarshalJSON_ZeroTime(t *testing.T) {
	rfc := RFC3339{T: time.Time{}}

	data, err := json.Marshal(rfc)
	assert.NoError(t, err)
	assert.Contains(t, string(data), "0001-01-01T00:00:00Z")
}

func TestRequest_JSONRoundTrip(t *testing.T) {
	req := Request{
		Operation: "download",
		Transfers: []string{"basic"},
		Objects: []RequestObject{
			{OID: "abc123", Size: 1024},
		},
	}

	data, err := json.Marshal(req)
	assert.NoError(t, err)

	var decoded Request
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, req.Operation, decoded.Operation)
	assert.Equal(t, req.Transfers, decoded.Transfers)
	assert.Len(t, decoded.Objects, 1)
	assert.Equal(t, "abc123", decoded.Objects[0].OID)
	assert.Equal(t, 1024, decoded.Objects[0].Size)
}

func TestResponse_JSONRoundTrip(t *testing.T) {
	resp := Response{
		Transfer: "basic",
		Objects: []Object{
			{
				OID:           "def456",
				Size:          2048,
				Authenticated: true,
				Actions: &Actions{
					Download: &Action{
						HRef:   "https://example.com/download",
						Header: map[string]string{"Authorization": "Bearer token"},
					},
				},
			},
		},
	}

	data, err := json.Marshal(resp)
	assert.NoError(t, err)

	var decoded Response
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, "basic", decoded.Transfer)
	assert.Len(t, decoded.Objects, 1)
	assert.Equal(t, "def456", decoded.Objects[0].OID)
	assert.NotNil(t, decoded.Objects[0].Actions)
	assert.NotNil(t, decoded.Objects[0].Actions.Download)
	assert.Equal(t, "https://example.com/download", decoded.Objects[0].Actions.Download.HRef)
}

func TestErrorResponse_JSONRoundTrip(t *testing.T) {
	errResp := ErrorResponse{
		Message:   "object not found",
		DocURL:    "https://docs.example.com",
		RequestID: "req-123",
	}

	data, err := json.Marshal(errResp)
	assert.NoError(t, err)

	var decoded ErrorResponse
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, errResp.Message, decoded.Message)
	assert.Equal(t, errResp.DocURL, decoded.DocURL)
	assert.Equal(t, errResp.RequestID, decoded.RequestID)
}

func TestSuccessResponse_JSONRoundTrip(t *testing.T) {
	succResp := SuccessResponse{
		Message: "ok",
		Data:    map[string]string{"key": "value"},
	}

	data, err := json.Marshal(succResp)
	assert.NoError(t, err)

	var decoded SuccessResponse
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, "ok", decoded.Message)
}

func TestObjectError_JSONRoundTrip(t *testing.T) {
	objErr := ObjectError{Code: 404, Message: "not found"}

	data, err := json.Marshal(objErr)
	assert.NoError(t, err)

	var decoded ObjectError
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, 404, decoded.Code)
	assert.Equal(t, "not found", decoded.Message)
}

func TestAction_WithExpiresAt(t *testing.T) {
	ts := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	action := Action{
		HRef:      "https://example.com/upload",
		Header:    map[string]string{"Authorization": "Bearer token"},
		ExpiresIn: 3600,
		ExpiresAt: &RFC3339{T: ts},
	}

	data, err := json.Marshal(action)
	assert.NoError(t, err)
	assert.Contains(t, string(data), `"expires_at":"2025-06-01T12:00:00Z"`)
	assert.Contains(t, string(data), `"href":"https://example.com/upload"`)
	assert.Contains(t, string(data), `"expires_in":3600`)
}

func TestOpenEulerAccountParam_JSONRoundTrip(t *testing.T) {
	param := OpenEulerAccountParam{
		AppId:     "app123",
		Url:       "/oauth/callback",
		GrantType: "authorization_code",
		AppSecret: "secret456",
	}

	data, err := json.Marshal(param)
	assert.NoError(t, err)

	var decoded OpenEulerAccountParam
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, "app123", decoded.AppId)
	assert.Equal(t, "authorization_code", decoded.GrantType)
}

func TestManagerTokenOutput_JSONRoundTrip(t *testing.T) {
	output := ManagerTokenOutput{
		MSG:    "success",
		Token:  "tok-abc",
		STATUS: 200,
	}

	data, err := json.Marshal(output)
	assert.NoError(t, err)

	var decoded ManagerTokenOutput
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, "success", decoded.MSG)
	assert.Equal(t, "tok-abc", decoded.Token)
	assert.Equal(t, 200, decoded.STATUS)
}

func TestOpenEulerUserInfo_JSONRoundTrip(t *testing.T) {
	info := OpenEulerUserInfo{
		Msg:  "ok",
		Code: 0,
		Data: OpenEulerUserData{
			Nickname: "testuser",
			Email:    "test@example.com",
			Username: "testuser",
			Identities: []Identity{
				{
					LoginName:   "testuser",
					UserIdInIdp: "idp-123",
					Identity:    "gitee",
					UserName:    "Test User",
					AccessToken: "at-xyz",
				},
			},
		},
	}

	data, err := json.Marshal(info)
	assert.NoError(t, err)

	var decoded OpenEulerUserInfo
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, "ok", decoded.Msg)
	assert.Equal(t, 0, decoded.Code)
	assert.Equal(t, "testuser", decoded.Data.Nickname)
	assert.Len(t, decoded.Data.Identities, 1)
	assert.Equal(t, "gitee", decoded.Data.Identities[0].Identity)
}
