package batch

import "time"

type Request struct {
	Operation string   `json:"operation"`
	Transfers []string `json:"transfers"`
	Ref       struct {
		Name string `json:"name"`
	} `json:"ref"`
	Objects []RequestObject `json:"objects"`
}

type RequestObject struct {
	OID  string `json:"oid"`
	Size int    `json:"size"`
}

type SuccessResponse struct {
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

type ErrorResponse struct {
	Message   string `json:"message"`
	DocURL    string `json:"documentation_url,omitempty"`
	RequestID string `json:"request_id,omitempty"`
}

type Action struct {
	HRef      string            `json:"href"`
	Header    map[string]string `json:"header,omitempty"`
	ExpiresIn int               `json:"expires_in,omitempty"` // seconds
	ExpiresAt *RFC3339          `json:"expires_at,omitempty"`
}

type Actions struct {
	Download *Action  `json:"download,omitempty"`
	Upload   *Action  `json:"upload,omitempty"`
	Verify   *Actions `json:"verify,omitempty"`
}

type ObjectError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type Object struct {
	OID           string       `json:"oid"`
	Size          int          `json:"size"`
	Authenticated bool         `json:"authenticated,omitempty"`
	Actions       *Actions     `json:"actions,omitempty"`
	Error         *ObjectError `json:"error,omitempty"`
}

type Response struct {
	Transfer string   `json:"transfer,omitempty"`
	Objects  []Object `json:"objects"`
}

type OpenEulerAccountParam struct {
	AppId     string `json:"app_id"`
	Url       string `json:"url_path"`
	GrantType string `json:"grant_type"`
	AppSecret string `json:"app_secret"`
}

type ManagerTokenOutput struct {
	MSG    string `json:"msg"`
	Token  string `json:"token"`
	STATUS int    `json:"status"`
}

type OpenEulerUserInfo struct {
	Msg  string            `json:"msg"`
	Code int               `json:"code"`
	Data OpenEulerUserData `json:"data"`
}

// 定义 OpenEulerUserData 结构体
type OpenEulerUserData struct {
	SignedUp         time.Time  `json:"signedUp"`
	Identities       []Identity `json:"identities"`
	PhoneCountryCode string     `json:"phoneCountryCode"`
	Phone            string     `json:"phone"`
	Nickname         string     `json:"nickname"`
	Photo            string     `json:"photo"`
	Company          string     `json:"company"`
	Email            string     `json:"email"`
	Username         string     `json:"username"`
}

// 定义 Identity 结构体
type Identity struct {
	LoginName   string `json:"login_name"`
	UserIdInIdp string `json:"userIdInIdp"`
	Identity    string `json:"identity"`
	UserName    string `json:"user_name"`
	AccessToken string `json:"accessToken"`
}

// --

// RFC3339 JSON-encodes a time.Time as an RFC3339 string
// (as opposed to RFC3339Nano, which is default behavior)
type RFC3339 struct {
	T time.Time
}

// MarshalJSON implements json.Marshaler
func (t RFC3339) MarshalJSON() ([]byte, error) {
	return t.T.Truncate(time.Second).MarshalJSON()
}
