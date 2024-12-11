package server

import (
	"errors"
	"github.com/huaweicloud/huaweicloud-sdk-go-obs/obs"
	"github.com/metalogical/BigFiles/auth"
	"github.com/metalogical/BigFiles/batch"
	"net/http"
	"net/url"
	"reflect"
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
	isAuthorized: auth.GiteeAuth(),
	bucket:       "Bucket",
	prefix:       "Prefix",
	cdnDomain:    "CDNDomain",
}

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
	type fields struct {
		Endpoint        string
		NoSSL           bool
		Bucket          string
		CdnDomain       string
		S3Accelerate    bool
		AccessKeyID     string
		SecretAccessKey string
		SessionToken    string
		TTL             time.Duration
		Prefix          string
		IsAuthorized    func(auth.UserInRepo) error
	}
	tests := []struct {
		name    string
		fields  fields
		want    Options
		wantErr bool
	}{
		{
			name: "Test Options imputeFromEnv Success",
			fields: fields{
				Endpoint:        "Endpoint",
				AccessKeyID:     "AccessKeyId",
				SecretAccessKey: "SecretAccessKey",
				SessionToken:    "SessionToken",
				Bucket:          "Bucket",
				TTL:             time.Hour,
			},
			want: Options{
				Endpoint:        "Endpoint",
				AccessKeyID:     "AccessKeyId",
				SecretAccessKey: "SecretAccessKey",
				SessionToken:    "SessionToken",
				Bucket:          "Bucket",
				TTL:             time.Hour,
			},
			wantErr: false,
		},
		{
			name: "Test Options endpoint Empty",
			fields: fields{
				AccessKeyID:     "AccessKeyId",
				SecretAccessKey: "SecretAccessKey",
				SessionToken:    "SessionToken",
				Bucket:          "Bucket",
				TTL:             time.Hour,
			},
			want: Options{
				AccessKeyID:     "AccessKeyId",
				SecretAccessKey: "SecretAccessKey",
				SessionToken:    "SessionToken",
				Bucket:          "Bucket",
				TTL:             time.Hour,
			},
			wantErr: true,
		},
		{
			name: "Test Options OBS_ACCESS_KEY_ID Empty",
			fields: fields{
				Endpoint:        "Endpoint",
				SecretAccessKey: "SecretAccessKey",
				SessionToken:    "SessionToken",
				Bucket:          "Bucket",
				TTL:             time.Hour,
			},
			want: Options{
				Endpoint:        "Endpoint",
				SecretAccessKey: "SecretAccessKey",
				SessionToken:    "SessionToken",
				Bucket:          "Bucket",
				TTL:             time.Hour,
			},
			wantErr: true,
		},
		{
			name: "Test Options Bucket Empty",
			fields: fields{
				Endpoint:        "Endpoint",
				AccessKeyID:     "AccessKeyId",
				SecretAccessKey: "SecretAccessKey",
				SessionToken:    "SessionToken",
				TTL:             time.Hour,
			},
			want: Options{
				Endpoint:        "Endpoint",
				AccessKeyID:     "AccessKeyId",
				SecretAccessKey: "SecretAccessKey",
				SessionToken:    "SessionToken",
				TTL:             time.Hour,
			},
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
			defer func() {
				if r := recover(); r != nil {
					// 如果捕获到了panic，检查错误信息是否符合预期
					err, ok := r.(error)
					if ok && tt.wantErr {
						if err.Error() == tt.args.err.Error() {
							return
						}
					}
					t.Errorf("unexpected panic value or wantErr mismatch")
				} else if tt.wantErr {
					t.Errorf("expected panic but none occurred")
				}
			}()
			must(tt.args.err)
		})
	}
}

func Test_server_dealWithAuthError(t *testing.T) {
	type args struct {
		userInRepo auth.UserInRepo
		w          http.ResponseWriter
		r          *http.Request
	}
	tests := []struct {
		name    string
		fields  ServerInfo
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
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
		name   string
		fields ServerInfo
		args   args
	}{
		// TODO: Add test cases.
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
			s.downloadObject(tt.args.in, tt.args.out)
		})
	}
}

func Test_server_generateDownloadUrl(t *testing.T) {
	type args struct {
		getObjectInput *obs.CreateSignedUrlInput
	}
	tests := []struct {
		name   string
		fields ServerInfo
		args   args
		want   *url.URL
	}{
		// TODO: Add test cases.
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
			if got := s.generateDownloadUrl(tt.args.getObjectInput); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("generateDownloadUrl() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_server_getObjectMetadataInput(t *testing.T) {
	type args struct {
		key string
	}
	tests := []struct {
		name       string
		fields     ServerInfo
		args       args
		wantOutput *obs.GetObjectMetadataOutput
		wantErr    bool
	}{
		// TODO: Add test cases.
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
			gotOutput, err := s.getObjectMetadataInput(tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("getObjectMetadataInput() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotOutput, tt.wantOutput) {
				t.Errorf("getObjectMetadataInput() gotOutput = %v, want %v", gotOutput, tt.wantOutput)
			}
		})
	}
}

func Test_server_handleBatch(t *testing.T) {
	type args struct {
		w http.ResponseWriter
		r *http.Request
	}
	tests := []struct {
		name   string
		fields ServerInfo
		args   args
	}{
		// TODO: Add test cases.
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
		// TODO: Add test cases.
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
	tests := []struct {
		name   string
		fields ServerInfo
		args   args
	}{
		// TODO: Add test cases.
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
		// TODO: Add test cases.
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
	tests := []struct {
		name   string
		fields ServerInfo
		args   args
	}{
		// TODO: Add test cases.
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
			s.uploadObject(tt.args.in, tt.args.out)
		})
	}
}
