package auth

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"io"
	"net/http"
	"testing"
)

func Test_getParsedResponse(t *testing.T) {
	type args struct {
		method string
		path   string
		header http.Header
		body   io.Reader
		obj    interface{}
	}
	tests := []struct {
		name    string
		args    args
		wantErr assert.ErrorAssertionFunc
	}{
		// TODO: Add test cases.
		{
			name: "Test GET request with correct repo and owner",
			args: args{
				method: "GET",
				path:   "https://gitee.com/api/v5/repos/src-openeuler/software-package-server",
				header: http.Header{contentType: []string{"application/json;charset=UTF-8"}},
				body:   nil,
				obj:    nil,
			},
			wantErr: assert.NoError,
		},
		{
			name: "Test GET request with wrong repo and owner",
			args: args{
				method: "GET",
				path:   "https://gitee.com/api/v5/repos/owner/repo",
				header: http.Header{contentType: []string{"application/json;charset=UTF-8"}},
				body:   nil,
				obj:    nil,
			},
			wantErr: assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.wantErr(t,
				getParsedResponse(tt.args.method, tt.args.path, tt.args.header, tt.args.body, tt.args.obj),
				fmt.Sprintf("getParsedResponse test, name:%v", tt.name))
		})
	}
}
