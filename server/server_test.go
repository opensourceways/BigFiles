package server

import (
	"bou.ke/monkey"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/go-chi/chi"
	"github.com/huaweicloud/huaweicloud-sdk-go-obs/obs"
	"github.com/metalogical/BigFiles/auth"
	"github.com/metalogical/BigFiles/batch"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

type ServerInfo struct {
	ttl          time.Duration
	client       *obs.ObsClient
	bucket       string
	prefix       string
	cdnDomain    string
	isAuthorized func(auth.UserInRepo) error
}

var serverInfo = ServerInfo{
	ttl:          time.Hour,
	bucket:       "Bucket",
	prefix:       "Prefix",
	cdnDomain:    "CDNDomain",
	isAuthorized: auth.GiteeAuth(),
}

const (
	batchUrlPath    = "/owner/repo/objects/batch"
	expectedPanic   = "expected panic but none occurred"
	unexpectedPanic = "unexpected panic value or wantErr mismatch"
)

func TestNew(t *testing.T) {
	type args struct {
		o Options
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "New Server failed",
			args: args{
				o: Options{
					Endpoint:        "Endpoint",
					AccessKeyID:     "AccessKeyId",
					SecretAccessKey: "SecretAccessKey",
					SessionToken:    "SessionToken",
					Bucket:          "Bucket",
					TTL:             time.Hour,
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.args.o)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestOptions_imputeFromEnv(t *testing.T) {
	optionsImputeFromEnvSuccess := Options{
		Endpoint:        "Endpoint",
		AccessKeyID:     "AccessKeyId",
		SecretAccessKey: "SecretAccessKey",
		SessionToken:    "SessionToken",
		Bucket:          "Bucket",
		TTL:             time.Hour,
	}
	optionsWithEmptyEndpoint := Options{
		AccessKeyID:     "AccessKeyId",
		SecretAccessKey: "SecretAccessKey",
		SessionToken:    "SessionToken",
		Bucket:          "Bucket",
		TTL:             time.Hour,
	}
	optionsWithEmptyObsAk := Options{
		Endpoint:        "Endpoint",
		SecretAccessKey: "SecretAccessKey",
		SessionToken:    "SessionToken",
		Bucket:          "Bucket",
		TTL:             time.Hour,
	}
	optionsWithEmptyBucket := Options{
		Endpoint:        "Endpoint",
		AccessKeyID:     "AccessKeyId",
		SecretAccessKey: "SecretAccessKey",
		SessionToken:    "SessionToken",
		TTL:             time.Hour,
	}
	tests := []struct {
		name    string
		fields  Options
		want    Options
		wantErr bool
	}{
		{
			name:    "Test Options imputeFromEnv Success",
			fields:  optionsImputeFromEnvSuccess,
			want:    optionsImputeFromEnvSuccess,
			wantErr: false,
		},
		{
			name:    "Test Options endpoint Empty",
			fields:  optionsWithEmptyEndpoint,
			want:    optionsWithEmptyEndpoint,
			wantErr: true,
		},
		{
			name:    "Test Options OBS_ACCESS_KEY_ID Empty",
			fields:  optionsWithEmptyObsAk,
			want:    optionsWithEmptyObsAk,
			wantErr: true,
		},
		{
			name:    "Test Options Bucket Empty",
			fields:  optionsWithEmptyBucket,
			want:    optionsWithEmptyBucket,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := Options{
				Endpoint:        tt.fields.Endpoint,
				NoSSL:           tt.fields.NoSSL,
				Bucket:          tt.fields.Bucket,
				CdnDomain:       tt.fields.CdnDomain,
				S3Accelerate:    tt.fields.S3Accelerate,
				AccessKeyID:     tt.fields.AccessKeyID,
				SecretAccessKey: tt.fields.SecretAccessKey,
				SessionToken:    tt.fields.SessionToken,
				TTL:             tt.fields.TTL,
				Prefix:          tt.fields.Prefix,
				IsAuthorized:    tt.fields.IsAuthorized,
			}
			got, err := o.imputeFromEnv()
			if (err != nil) != tt.wantErr {
				t.Errorf("imputeFromEnv() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("imputeFromEnv() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_must(t *testing.T) {
	type args struct {
		err error
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		// 测试传入nil，期望不会触发panic，也就是正常执行
		{
			name:    "no error",
			args:    args{err: nil},
			wantErr: false,
		},
		// 测试传入一个具体错误，期望触发panic
		{
			name:    "panic error",
			args:    args{err: errors.New("panic error test")},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer panicCheck(t, tt.wantErr)
			must(tt.args.err)
		})
	}
}

func panicCheck(t *testing.T, wantErr bool) {
	if r := recover(); r != nil {
		// 如果捕获到了panic，检查错误信息是否符合预期
		_, ok := r.(error)
		if ok && wantErr {
			return
		} else {
			t.Error(unexpectedPanic)
		}
	} else if wantErr {
		t.Error(expectedPanic)
	} else {
		return
	}

}

func Test_server_dealWithAuthError(t *testing.T) {
	type args struct {
		userInRepo auth.UserInRepo
		w          http.ResponseWriter
		r          *http.Request
	}
	validatecfg.passwordRegexp, _ = regexp.Compile(`^[a-zA-Z0-9!@_#$%^&*()-=+,?.,]*$`)
	validatecfg.usernameRegexp, _ = regexp.Compile(`^[a-zA-Z]([-_.]?[a-zA-Z0-9]+)*$`)
	username := "user"
	password := ""
	authString := fmt.Sprintf("%s:%s", username, password)
	encodedAuth := base64.StdEncoding.EncodeToString([]byte(authString))
	req := httptest.NewRequest(http.MethodGet, batchUrlPath, nil)
	req.Header.Set("Authorization", "Basic "+encodedAuth)
	tests := []struct {
		name    string
		fields  ServerInfo
		args    args
		wantErr bool
	}{
		{
			name:   "deal with auth without username and password",
			fields: serverInfo,
			args: args{
				r: httptest.NewRequest(http.MethodGet, batchUrlPath, nil),
			},
			wantErr: true,
		},
		{
			name:   "deal with auth with username and password failed",
			fields: serverInfo,
			args: args{
				r: req,
			},
			wantErr: true,
		},
		{
			name: "deal with auth with username and password success",
			fields: ServerInfo{
				isAuthorized: func(auth.UserInRepo) error { return nil },
			},
			args: args{
				r: req,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &server{
				ttl:          tt.fields.ttl,
				client:       tt.fields.client,
				bucket:       tt.fields.bucket,
				prefix:       tt.fields.prefix,
				cdnDomain:    tt.fields.cdnDomain,
				isAuthorized: tt.fields.isAuthorized,
			}
			w := httptest.NewRecorder()
			tt.args.w = w
			if err := s.dealWithAuthError(tt.args.userInRepo, tt.args.w, tt.args.r); (err != nil) != tt.wantErr {
				t.Errorf("dealWithAuthError() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_server_downloadObject(t *testing.T) {
	type args struct {
		in  *batch.RequestObject
		out *batch.Object
	}
	tests := []struct {
		name          string
		fields        ServerInfo
		args          args
		wantErr       bool
		mockMetaData  bool
		mockMetaSize  bool
		wantErrorCode int
	}{
		{
			name:   "download object success",
			fields: serverInfo,
			args: args{
				in: &batch.RequestObject{
					OID:  "123456789",
					Size: 100,
				},
				out: &batch.Object{
					OID:  "123456789",
					Size: 100,
				},
			},
			wantErr:      false,
			mockMetaData: true,
			mockMetaSize: true,
		},
		{
			name:   "download getObjectMetadataInput failed",
			fields: serverInfo,
			args: args{
				in: &batch.RequestObject{
					OID:  "123456789",
					Size: 100,
				},
				out: &batch.Object{
					OID:  "123456789",
					Size: 100,
				},
			},
			wantErr:       false,
			mockMetaData:  false,
			mockMetaSize:  true,
			wantErrorCode: 404,
		},
		{
			name:   "download getObjectMetadataInput size error",
			fields: serverInfo,
			args: args{
				in: &batch.RequestObject{
					OID:  "123456789",
					Size: 100,
				},
				out: &batch.Object{
					OID:  "123456789",
					Size: 100,
				},
			},
			wantErr:       false,
			mockMetaData:  false,
			mockMetaSize:  false,
			wantErrorCode: 422,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := obs.GetObjectMetadataOutput{
				ContentLength: int64(tt.args.in.Size),
			}
			getObjectMetadataInputPtr := reflect.ValueOf((*server).getObjectMetadataInput)
			if tt.mockMetaData {
				monkey.Patch(getObjectMetadataInputPtr.Interface(),
					func(s *server, key string) (output *obs.GetObjectMetadataOutput, err error) {
						return &o, nil
					})
			} else if tt.mockMetaSize {
				monkey.Patch(getObjectMetadataInputPtr.Interface(),
					func(s *server, key string) (output *obs.GetObjectMetadataOutput, err error) {
						return &o, errors.New("get Metadata error")
					})
			} else {
				monkey.Patch(getObjectMetadataInputPtr.Interface(),
					func(s *server, key string) (output *obs.GetObjectMetadataOutput, err error) {
						o.ContentLength = int64(101)
						return &o, nil
					})
			}

			defer monkey.Unpatch(getObjectMetadataInputPtr.Interface())
			downloadUrl, _ := url.Parse("test.url")
			generateDownloadUrlPtr := reflect.ValueOf((*server).generateDownloadUrl)
			monkey.Patch(generateDownloadUrlPtr.Interface(),
				func(s *server, getObjectInput *obs.CreateSignedUrlInput) *url.URL {
					return downloadUrl
				})
			defer monkey.Unpatch(generateDownloadUrlPtr.Interface())
			s := &server{
				ttl:          tt.fields.ttl,
				client:       tt.fields.client,
				bucket:       tt.fields.bucket,
				prefix:       tt.fields.prefix,
				cdnDomain:    tt.fields.cdnDomain,
				isAuthorized: tt.fields.isAuthorized,
			}
			defer panicCheck(t, tt.wantErr)
			s.downloadObject(tt.args.in, tt.args.out)
			if tt.args.out.Error != nil && tt.args.out.Error.Code != tt.wantErrorCode {
				t.Errorf("download failed with unexpected code = %v", tt.args.out.Error.Code)
			}
		})
	}
}

func Test_server_generateDownloadUrl(t *testing.T) {
	type args struct {
		getObjectInput *obs.CreateSignedUrlInput
	}
	inputObject := &obs.CreateSignedUrlInput{
		Method:  obs.HttpMethodGet,
		Bucket:  serverInfo.bucket,
		Key:     "123456789",
		Expires: int(serverInfo.ttl / time.Second),
		Headers: map[string]string{contentType: "application/octet-stream"},
	}
	tests := []struct {
		name    string
		fields  ServerInfo
		args    args
		wantErr bool
	}{
		{
			name:   "generate download url",
			fields: serverInfo,
			args: args{
				getObjectInput: inputObject,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &server{
				ttl:          tt.fields.ttl,
				client:       tt.fields.client,
				bucket:       tt.fields.bucket,
				prefix:       tt.fields.prefix,
				cdnDomain:    tt.fields.cdnDomain,
				isAuthorized: tt.fields.isAuthorized,
			}
			defer panicCheck(t, tt.wantErr)
			if got := s.generateDownloadUrl(tt.args.getObjectInput); got != nil {
				t.Errorf("generateDownloadUrl() = %v", got)
			}
		})
	}
}

func Test_server_getObjectMetadataInput(t *testing.T) {
	type args struct {
		key string
	}
	tests := []struct {
		name    string
		fields  ServerInfo
		args    args
		wantErr bool
	}{
		{
			name:   "getObjectMetadataInput success",
			fields: serverInfo,
			args: args{
				key: "123456789",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &server{
				ttl:          tt.fields.ttl,
				client:       tt.fields.client,
				bucket:       tt.fields.bucket,
				prefix:       tt.fields.prefix,
				cdnDomain:    tt.fields.cdnDomain,
				isAuthorized: tt.fields.isAuthorized,
			}
			defer panicCheck(t, tt.wantErr)
			_, err := s.getObjectMetadataInput(tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("getObjectMetadataInput() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_server_handleBatch(t *testing.T) {
	type args struct {
		w http.ResponseWriter
		r *http.Request
	}
	requestBodyText := `{
				"operation": "download",
				"objects": [
						{
							"oid": "123456",
							"Size": 100
						}
					]
				}`
	requestBody := strings.NewReader(requestBodyText)
	owner := "test_owner"
	repo := "test_repo"
	// 创建一个带有路径参数的请求路径，这里将owner作为路径参数添加到URL中
	requestPath := "/{owner}/{repo}/objects/batch"
	req := httptest.NewRequest(http.MethodGet, requestPath, requestBody)
	ctx := chi.NewRouteContext()
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, ctx))
	ctx.URLParams.Add("owner", owner)
	ctx.URLParams.Add("repo", repo)
	validatecfg.ownerRegexp, _ = regexp.Compile(`^[a-zA-Z]([-_.]?[a-zA-Z0-9]+)*$`)
	validatecfg.reponameRegexp, _ = regexp.Compile(`^[a-zA-Z0-9_.-]{1,189}[a-zA-Z0-9]$`)
	tests := []struct {
		name                  string
		args                  args
		wantErr               bool
		fields                ServerInfo
		wantDealWithAuthError bool
	}{
		{
			name:   "server handleBatch success with nil requestBody",
			fields: serverInfo,
			args: args{
				r: httptest.NewRequest(http.MethodGet, batchUrlPath, nil),
			},
			wantErr:               false,
			wantDealWithAuthError: false,
		},
		{
			name:   "server handleBatch success",
			fields: serverInfo,
			args: args{
				r: req,
			},
			wantErr:               false,
			wantDealWithAuthError: false,
		},
		{
			name:   "server handleBatch dealWithAuthError success",
			fields: serverInfo,
			args: args{
				r: req,
			},
			wantErr:               false,
			wantDealWithAuthError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantDealWithAuthError {
				dealWithAuthErrorPtr := reflect.ValueOf((*server).dealWithAuthError)
				monkey.Patch(dealWithAuthErrorPtr.Interface(),
					func(s *server, userInRepo auth.UserInRepo, w http.ResponseWriter, r *http.Request) error {
						return nil
					})
				defer monkey.Unpatch(dealWithAuthErrorPtr.Interface())
			}
			s := &server{
				ttl:          tt.fields.ttl,
				client:       tt.fields.client,
				bucket:       tt.fields.bucket,
				prefix:       tt.fields.prefix,
				cdnDomain:    tt.fields.cdnDomain,
				isAuthorized: tt.fields.isAuthorized,
			}
			w := httptest.NewRecorder()
			tt.args.w = w
			defer panicCheck(t, tt.wantErr)
			s.handleBatch(tt.args.w, tt.args.r)
		})
	}
}

func Test_server_handleRequestObject(t *testing.T) {
	type args struct {
		req batch.Request
	}
	tests := []struct {
		name   string
		fields ServerInfo
		args   args
		want   batch.Response
	}{
		{
			name:   "server handleRequestObject",
			fields: serverInfo,
			args: args{
				req: batch.Request{
					Operation: "download",
					Objects: []batch.RequestObject{
						{
							OID:  "123456789",
							Size: 1000,
						},
					},
				},
			},
			want: batch.Response{
				Objects: []batch.Object{
					{
						OID:  "123456789",
						Size: 1000,
						Error: &batch.ObjectError{
							Code:    422,
							Message: "oid must be a SHA-256 hash in lower case hexadecimal",
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &server{
				ttl:          tt.fields.ttl,
				client:       tt.fields.client,
				bucket:       tt.fields.bucket,
				prefix:       tt.fields.prefix,
				cdnDomain:    tt.fields.cdnDomain,
				isAuthorized: tt.fields.isAuthorized,
			}
			if got := s.handleRequestObject(tt.args.req); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("handleRequestObject() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_server_healthCheck(t *testing.T) {
	type args struct {
		w http.ResponseWriter
		r *http.Request
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	tests := []struct {
		name    string
		fields  ServerInfo
		args    args
		wantErr bool
	}{
		{
			name:   "server healthCheck success",
			fields: serverInfo,
			args: args{
				r: req,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &server{
				ttl:          tt.fields.ttl,
				client:       tt.fields.client,
				bucket:       tt.fields.bucket,
				prefix:       tt.fields.prefix,
				cdnDomain:    tt.fields.cdnDomain,
				isAuthorized: tt.fields.isAuthorized,
			}
			w := httptest.NewRecorder()
			tt.args.w = w
			defer panicCheck(t, tt.wantErr)
			s.healthCheck(tt.args.w, tt.args.r)
		})
	}
}

func Test_server_key(t *testing.T) {
	type args struct {
		oid string
	}
	tests := []struct {
		name   string
		fields ServerInfo
		args   args
		want   string
	}{
		{
			name:   "server key test success",
			fields: serverInfo,
			args: args{
				oid: "123456789",
			},
			want: "Prefix123456789",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &server{
				ttl:          tt.fields.ttl,
				client:       tt.fields.client,
				bucket:       tt.fields.bucket,
				prefix:       tt.fields.prefix,
				cdnDomain:    tt.fields.cdnDomain,
				isAuthorized: tt.fields.isAuthorized,
			}
			if got := s.key(tt.args.oid); got != tt.want {
				t.Errorf("key() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_server_uploadObject(t *testing.T) {
	type args struct {
		in  *batch.RequestObject
		out *batch.Object
	}
	outWithLarge := batch.Object{
		OID:  "123456789",
		Size: 5 * int(math.Pow10(9)),
	}
	outObject := batch.Object{
		OID:  "123456789",
		Size: 1000,
	}
	inObject := batch.RequestObject{
		OID: "123456789",
	}
	tests := []struct {
		name        string
		args        args
		wantErr     bool
		fields      ServerInfo
		wantGetMeta bool
	}{
		{
			name:   "server uploadObject size large than limit",
			fields: serverInfo,
			args: args{
				out: &outWithLarge,
			},
			wantErr: false,
		},
		{
			name:   "server upload size smaller than limit",
			fields: serverInfo,
			args: args{
				out: &outObject,
			},
			wantErr: true,
		},
		{
			name:   "server upload get metadata success",
			fields: serverInfo,
			args: args{
				in:  &inObject,
				out: &outObject,
			},
			wantErr:     false,
			wantGetMeta: true,
		},
		{
			name:   "server upload get metadata success",
			fields: serverInfo,
			args: args{
				in:  &inObject,
				out: &outObject,
			},
			wantErr:     true,
			wantGetMeta: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getObjectMetadataInputPtr := reflect.ValueOf((*server).getObjectMetadataInput)
			if tt.wantGetMeta {
				monkey.Patch(getObjectMetadataInputPtr.Interface(),
					func(s *server, key string) (output *obs.GetObjectMetadataOutput, err error) {
						return &obs.GetObjectMetadataOutput{}, nil
					})
			} else {
				monkey.Patch(getObjectMetadataInputPtr.Interface(),
					func(s *server, key string) (output *obs.GetObjectMetadataOutput, err error) {
						return &obs.GetObjectMetadataOutput{}, errors.New("get meta data error")
					})
			}
			defer monkey.Unpatch(getObjectMetadataInputPtr.Interface())
			s := &server{
				ttl:          tt.fields.ttl,
				client:       tt.fields.client,
				bucket:       tt.fields.bucket,
				prefix:       tt.fields.prefix,
				cdnDomain:    tt.fields.cdnDomain,
				isAuthorized: tt.fields.isAuthorized,
			}
			defer panicCheck(t, tt.wantErr)
			s.uploadObject(tt.args.in, tt.args.out)
		})
	}
}
