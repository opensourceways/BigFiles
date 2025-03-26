package server

import (
	"bou.ke/monkey"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-chi/chi"
	"github.com/huaweicloud/huaweicloud-sdk-go-obs/obs"
	"github.com/metalogical/BigFiles/auth"
	"github.com/metalogical/BigFiles/batch"
	"github.com/metalogical/BigFiles/db"
	"github.com/stretchr/testify/assert"
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
		name                string
		fields              ServerInfo
		args                args
		wantErr             bool
		mockMetaData        bool
		mockMetaSize        bool
		wantErrorCode       int
		mockReturnEmptyList bool
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
			wantErr:             false,
			mockMetaData:        true,
			mockMetaSize:        true,
			mockReturnEmptyList: false,
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
			wantErr:             false,
			mockMetaData:        false,
			mockMetaSize:        false,
			wantErrorCode:       422,
			mockReturnEmptyList: false,
		},
	}
	var mockReturnEmptyList bool
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockReturnEmptyList = tt.mockReturnEmptyList
			monkey.Patch(db.SelectLfsObjByOid, func(oid string) ([]db.LfsObj, error) {
				if mockReturnEmptyList {
					return []db.LfsObj{}, nil // 返回空列表
				}
				return []db.LfsObj{
					{
						Oid:   oid,
						Exist: 1,
					},
				}, nil // 返回一个包含对象的列表
			})
			defer monkey.UnpatchAll() // 恢复原始实现
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

func Test_server_List(t *testing.T) {
	type args struct {
		w http.ResponseWriter
		r *http.Request
	}
	owner := "test_owner"
	repo := "test_repo"
	platform := "test_platform"
	page := 1
	limit := 10

	// 创建一个带有路径参数和查询参数的请求路径
	requestPath := fmt.Sprintf("/%s/%s?platform=%s&page=%d&limit=%d", owner, repo, platform, page, limit)
	req := httptest.NewRequest(http.MethodGet, requestPath, nil)
	ctx := chi.NewRouteContext()
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, ctx))
	ctx.URLParams.Add("owner", owner)
	ctx.URLParams.Add("repo", repo)

	// 模拟 getLfsFiles 和 countLfsFiles 的返回值
	mockFiles := []db.LfsObj{
		{Oid: "123456", Size: 100},
		{Oid: "789012", Size: 200},
	}
	mockTotal := int64(2)

	tests := []struct {
		name    string
		args    args
		wantErr bool
		fields  ServerInfo
	}{
		{
			name:   "server List success",
			fields: ServerInfo{
				// 初始化 ServerInfo 字段
			},
			args: args{
				r: req,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 模拟 getLfsFiles 和 countLfsFiles 函数
			monkey.Patch((*server).getLfsFiles, func(s *server, owner, repo,
				platform string, page, limit int) ([]db.LfsObj, error) {
				return mockFiles, nil
			})
			monkey.Patch((*server).countLfsFiles, func(s *server, owner, repo, platform string) (int64, error) {
				return mockTotal, nil
			})
			defer monkey.UnpatchAll()

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

			s.List(tt.args.w, tt.args.r)

			// 调用验证函数
			validateListResponse(t, w, mockFiles, mockTotal)
		})
	}
}

// 验证响应状态码、内容类型和响应体
func validateListResponse(t *testing.T, w *httptest.ResponseRecorder, mockFiles []db.LfsObj, mockTotal int64) {
	// 验证响应状态码
	if w.Code != http.StatusOK {
		t.Errorf("expected response status code %d, got %d", http.StatusOK, w.Code)
	}

	// 验证响应内容类型
	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("expected content type %s, got %s", "application/json", contentType)
	}

	type FileResponse struct {
		Owner      string `json:"owner"`       // 文件所有者
		Repo       string `json:"repo"`        // 仓库名称
		Size       int    `json:"size"`        // 文件大小
		Oid        string `json:"oid"`         // 文件 OID
		CreateTime int64  `json:"create_time"` // 创建时间
		UpdateTime int64  `json:"update_time"` // 更新时间
	}

	type ListResponse struct {
		Total int            `json:"total"` // 文件总数
		Files []FileResponse `json:"files"` // 文件列表
	}

	// 验证响应体
	var resp ListResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Errorf("failed to decode response body: %v", err)
	}

	if len(resp.Files) != len(mockFiles) {
		t.Errorf("expected %d files, got %d", len(mockFiles), len(resp.Files))
	}

	if resp.Total != int(mockTotal) {
		t.Errorf("expected total %d, got %d", mockTotal, resp.Total)
	}
}

func TestBuildListResponse(t *testing.T) {
	// 固定时间，用于创建测试数据
	now := time.Now()

	// 测试文件数据
	total := int64(2) // 预期的文件总数
	files := []db.LfsObj{
		{
			ID:         1,
			Owner:      "owner1",
			Repo:       "repo1",
			Size:       1234,
			Oid:        "oid1",
			CreateTime: now,
			UpdateTime: now,
			Platform:   "gitee",
			Operator:   "operator1",
			Exist:      1,
		},
		{
			ID:         2,
			Owner:      "owner2",
			Repo:       "repo2",
			Size:       5678,
			Oid:        "oid2",
			CreateTime: now,
			UpdateTime: now,
			Platform:   "gitee",
			Operator:   "operator2",
			Exist:      1,
		},
	}

	// 创建 server 实例
	s := &server{}

	// 调用 buildListResponse
	response := s.buildListResponse(files, total)

	// 进行断言，确保返回的结构符合预期
	result := response.(struct {
		Total int            `json:"total"`
		Files []FileResponse `json:"files"`
	})

	// 验证结果
	assert.Equal(t, total, int64(result.Total))
	assert.Equal(t, "owner1", result.Files[0].Owner)
	assert.Equal(t, "repo1", result.Files[0].Repo)
	assert.Equal(t, 1234, result.Files[0].Size)
	assert.Equal(t, "oid1", result.Files[0].Oid)

	assert.Equal(t, "owner2", result.Files[1].Owner)
	assert.Equal(t, "repo2", result.Files[1].Repo)
	assert.Equal(t, 5678, result.Files[1].Size)
	assert.Equal(t, "oid2", result.Files[1].Oid)
}

func TestBuildListAllReposResponse(t *testing.T) {
	// 测试数据
	total := int64(2)
	repoList := []struct {
		Owner         string    `json:"owner"`
		Repo          string    `json:"repo"`
		TotalSize     int       `json:"total_size"`
		Time          int64     `json:"time"`
		FirstFileTime time.Time `json:"first_file_time"`
	}{
		{
			Owner:         "owner1",
			Repo:          "repo1",
			TotalSize:     100,
			Time:          time.Now().Unix(),
			FirstFileTime: time.Now(),
		},
		{
			Owner:         "owner2",
			Repo:          "repo2",
			TotalSize:     200,
			Time:          time.Now().Unix(),
			FirstFileTime: time.Now(),
		},
	}

	// 创建 server 实例
	s := &server{}

	// 调用 buildListAllReposResponse
	response := s.buildListAllReposResponse(total, repoList)

	// 进行断言，确保返回的结构符合预期
	result := response.(struct {
		Total int `json:"total"`
		Repos []struct {
			Owner         string    `json:"owner"`
			Repo          string    `json:"repo"`
			TotalSize     int       `json:"total_size"`
			Time          int64     `json:"time"`
			FirstFileTime time.Time `json:"first_file_time"`
		} `json:"repos"`
	})

	// 验证结果
	assert.Equal(t, 2, result.Total)
	assert.Equal(t, "owner1", result.Repos[0].Owner)
	assert.Equal(t, "repo1", result.Repos[0].Repo)
	assert.Equal(t, 100, result.Repos[0].TotalSize)
	assert.Equal(t, "owner2", result.Repos[1].Owner)
	assert.Equal(t, "repo2", result.Repos[1].Repo)
	assert.Equal(t, 200, result.Repos[1].TotalSize)
}

func TestGetQueryParams(t *testing.T) {
	s := &server{}

	// 创建一个 HTTP 请求模拟
	tests := []struct {
		url           string
		expectedKey   string
		expectedPage  int
		expectedLimit int
	}{
		{"/?searchKey=test&page=1&limit=5", "test", 1, 5},
		{"/?searchKey=test&page=2", "test", 2, 0},
		{"/?searchKey=test&limit=10", "test", 1, 10},
		{"/?page=3&limit=3", "", 3, 3},
		{"/?page=0&limit=3", "", 1, 3},                    // page 0 should fallback to 1
		{"/?page=abc&limit=3", "", 1, 3},                  // invalid page should fallback
		{"/?searchKey=test&page=2&limit=0", "test", 2, 0}, // limit 0 should remain 0
		{"/", "", 1, 0}, // no query parameters
	}

	for _, test := range tests {
		req := httptest.NewRequest("GET", test.url, nil)
		key, page, limit := s.getQueryParams(req)

		// 使用 assert 来验证结果
		assert.Equal(t, test.expectedKey, key)
		assert.Equal(t, test.expectedPage, page)
		assert.Equal(t, test.expectedLimit, limit)
	}
}

func TestDownload(t *testing.T) {
	type args struct {
		w http.ResponseWriter
		r *http.Request
	}

	// 创建测试用例
	tests := []struct {
		name       string
		fields     ServerInfo
		args       args
		wantErr    bool
		oid        string
		mockError  error
		mockOutput string
	}{
		{
			name: "Valid OID - Success",
			fields: ServerInfo{
				bucket:    "test-bucket",
				ttl:       3600 * time.Second,
				cdnDomain: "test-cdn.example.com",
			},
			args: args{
				r: httptest.NewRequest(http.MethodGet, "/download/valid_oid", nil),
			},
			wantErr:    false,
			oid:        "valid_oid",
			mockOutput: "https://example.com/download/valid_oid",
		},
		{
			name: "Invalid OID - Not Found",
			fields: ServerInfo{
				bucket:    "test-bucket",
				ttl:       3600 * time.Second,
				cdnDomain: "test-cdn.example.com",
			},
			args: args{
				r: httptest.NewRequest(http.MethodGet, "/download/invalid_oid", nil),
			},
			wantErr:   true,
			oid:       "invalid_oid",
			mockError: errors.New("Object not found"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 初始化 server 实例
			s := &server{
				ttl:          tt.fields.ttl,
				client:       tt.fields.client,
				bucket:       tt.fields.bucket,
				prefix:       tt.fields.prefix,
				cdnDomain:    tt.fields.cdnDomain,
				isAuthorized: tt.fields.isAuthorized,
			}

			// 创建 chi 路由上下文并设置 OID 参数
			ctx := chi.NewRouteContext()
			ctx.URLParams.Add("oid", tt.oid)
			req := tt.args.r.WithContext(context.WithValue(tt.args.r.Context(), chi.RouteCtxKey, ctx))

			// 创建 ResponseRecorder 记录响应
			w := httptest.NewRecorder()
			tt.args.w = w

			// 模拟 getObjectMetadataInput 的行为
			monkey.Patch((*server).getObjectMetadataInput, func(s *server, key string) (*obs.GetObjectMetadataOutput, error) {
				if tt.mockError != nil {
					return nil, tt.mockError
				}
				return &obs.GetObjectMetadataOutput{}, nil
			})
			defer monkey.UnpatchAll()

			// 模拟 generateDownloadUrl 的行为
			monkey.Patch((*server).generateDownloadUrl, func(s *server, input *obs.CreateSignedUrlInput) *url.URL {
				u, _ := url.Parse(tt.mockOutput)
				return u
			})
			defer monkey.UnpatchAll()

			// 调用 download 函数
			s.download(tt.args.w, req)

			// 调用验证函数
			if tt.wantErr {
				validateErrorResponse(t, w, http.StatusNotFound, tt.mockError)
			} else {
				validateSuccessResponse(t, w, tt.mockOutput)
			}
		})
	}
}

// 验证成功响应
func validateSuccessResponse(t *testing.T, w *httptest.ResponseRecorder, expectedURL string) {
	// 验证响应状态码
	if w.Code != http.StatusOK {
		t.Errorf("expected status code %d, got %d", http.StatusOK, w.Code)
	}

	// 验证成功响应体
	var response map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Errorf("failed to decode response body: %v", err)
	}
	if url, ok := response["url"]; !ok || url != expectedURL {
		t.Errorf("expected response to contain 'url': '%s', got %v", expectedURL, response)
	}
}

// 验证错误响应
func validateErrorResponse(t *testing.T, w *httptest.ResponseRecorder, expectedStatusCode int, expectedError error) {
	// 验证响应状态码
	if w.Code != expectedStatusCode {
		t.Errorf("expected status code %d, got %d", expectedStatusCode, w.Code)
	}

	// 验证错误响应体
	var errorResponse batch.ObjectError
	if err := json.Unmarshal(w.Body.Bytes(), &errorResponse); err != nil {
		t.Errorf("failed to decode error response body: %v", err)
	}
	if errorResponse.Code != expectedStatusCode || errorResponse.Message != expectedError.Error() {
		t.Errorf("expected error response {Code: %d, Message: '%s'}, got %v",
			expectedStatusCode, expectedError.Error(), errorResponse)
	}
}

func TestParsePaginationParams(t *testing.T) {
	type args struct {
		r *http.Request
	}

	tests := []struct {
		name      string
		args      args
		wantPage  int
		wantLimit int
	}{
		{
			name: "Default values",
			args: args{
				r: httptest.NewRequest(http.MethodGet, "/", nil),
			},
			wantPage:  1,
			wantLimit: 10,
		},
		{
			name: "Valid page and limit",
			args: args{
				r: httptest.NewRequest(http.MethodGet, "/?page=2&limit=20", nil),
			},
			wantPage:  2,
			wantLimit: 20,
		},
		{
			name: "Invalid page (negative value)",
			args: args{
				r: httptest.NewRequest(http.MethodGet, "/?page=-1&limit=20", nil),
			},
			wantPage:  1, // 默认值
			wantLimit: 20,
		},
		{
			name: "Invalid limit (non-numeric value)",
			args: args{
				r: httptest.NewRequest(http.MethodGet, "/?page=2&limit=abc", nil),
			},
			wantPage:  2,
			wantLimit: 10, // 默认值
		},
		{
			name: "Missing limit",
			args: args{
				r: httptest.NewRequest(http.MethodGet, "/?page=3", nil),
			},
			wantPage:  3,
			wantLimit: 10, // 默认值
		},
		{
			name: "Missing page",
			args: args{
				r: httptest.NewRequest(http.MethodGet, "/?limit=15", nil),
			},
			wantPage:  1, // 默认值
			wantLimit: 15,
		},
		{
			name: "Page and limit both invalid",
			args: args{
				r: httptest.NewRequest(http.MethodGet, "/?page=abc&limit=-5", nil),
			},
			wantPage:  1,  // 默认值
			wantLimit: 10, // 默认值
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPage, gotLimit := parsePaginationParams(tt.args.r)
			if gotPage != tt.wantPage {
				t.Errorf("parsePaginationParams() gotPage = %v, want %v", gotPage, tt.wantPage)
			}
			if gotLimit != tt.wantLimit {
				t.Errorf("parsePaginationParams() gotLimit = %v, want %v", gotLimit, tt.wantLimit)
			}
		})
	}
}
