package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"math"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"github.com/huaweicloud/huaweicloud-sdk-go-obs/obs"
	"github.com/metalogical/BigFiles/auth"
	"github.com/metalogical/BigFiles/batch"
	"github.com/metalogical/BigFiles/db"
)

var ObsPutLimit int = 5*int(math.Pow10(9)) - 1 // 5GB - 1
var oidRegexp = regexp.MustCompile("^[a-f0-9]{64}$")
var contentType = "Content-Type"

type Options struct {
	// required
	Endpoint     string
	NoSSL        bool
	Bucket       string
	CdnDomain    string
	S3Accelerate bool

	// minio auth (required)
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string

	// optional
	TTL    time.Duration // defaults to 1 hour
	Prefix string

	IsAuthorized func(auth.UserInRepo) error
}

func (o Options) imputeFromEnv() (Options, error) {
	if o.Endpoint == "" {
		region := os.Getenv("OBS_REGION")
		if region == "" {
			return o, errors.New("endpoint required")
		}
		o.Endpoint = region
	}
	if o.AccessKeyID == "" {
		o.AccessKeyID = os.Getenv("OBS_ACCESS_KEY_ID")
		if o.AccessKeyID == "" {
			return o, fmt.Errorf("OBS access key ID required for %s", o.Endpoint)
		}
		o.SecretAccessKey = os.Getenv("OBS_SECRET_ACCESS_KEY")
		if o.SecretAccessKey == "" {
			return o, fmt.Errorf("OBS secret access key required for %s", o.Endpoint)
		}
		o.SessionToken = os.Getenv("OBS_SESSION_TOKEN")
	}
	if o.Bucket == "" {
		return o, fmt.Errorf("bucket required")
	}
	if o.TTL == 0 {
		o.TTL = time.Hour
	}

	return o, nil
}

func New(o Options) (http.Handler, error) {
	o, err := o.imputeFromEnv()
	if err != nil {
		return nil, err
	}

	client, err := obs.New(o.AccessKeyID, o.SecretAccessKey, o.Endpoint, obs.WithSignature(obs.SignatureObs))
	if err != nil {
		return nil, err
	}

	s := &server{
		ttl:          o.TTL,
		client:       client,
		bucket:       o.Bucket,
		prefix:       o.Prefix,
		cdnDomain:    o.CdnDomain,
		isAuthorized: o.IsAuthorized,
	}

	r := chi.NewRouter()

	r.Get("/", s.healthCheck)
	r.Post("/{owner}/{repo}/objects/batch", s.handleBatch)
	r.Get("/{owner}/{repo}/object/list?platform=", s.List)
	r.Get("/info/lfs/objects/{oid}", s.download)

	return r, nil
}

type server struct {
	ttl       time.Duration
	client    *obs.ObsClient
	bucket    string
	prefix    string
	cdnDomain string

	isAuthorized func(auth.UserInRepo) error
}

func (s *server) key(oid string) string {
	return s.prefix + oid
}

func (s *server) handleBatch(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(contentType, "application/vnd.git-lfs+json")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	var req batch.Request
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		must(json.NewEncoder(w).Encode(batch.ErrorResponse{
			Message: "could not parse request",
			DocURL:  "https://github.com/git-lfs/git-lfs/blob/v2.12.0/docs/api/batch.md#requests",
		}))
		return
	}

	var userInRepo auth.UserInRepo
	userInRepo.Operation = req.Operation
	userInRepo.Owner = chi.URLParam(r, "owner")
	userInRepo.Repo = chi.URLParam(r, "repo")

	if !validatecfg.ownerRegexp.MatchString(userInRepo.Owner) || !validatecfg.reponameRegexp.MatchString(userInRepo.Repo) {
		w.WriteHeader(http.StatusBadRequest)
		must(json.NewEncoder(w).Encode(batch.ErrorResponse{
			Message: "invalid owner or reponame format",
		}))
		return
	}

	if err = auth.CheckRepoOwner(userInRepo); req.Operation == "upload" || err != nil {
		err := s.dealWithAuthError(userInRepo, w, r)
		if err != nil {
			return
		}
	}

	resp := s.handleRequestObject(req)

	// 添加元数据
	if req.Operation == "upload" {
		for _, object := range req.Objects {
			lfsObj := db.LfsObj{
				Repo:     userInRepo.Repo,
				Owner:    userInRepo.Owner,
				Oid:      object.OID,
				Size:     object.Size,
				Exist:    1,       // 默认设置为存在
				Platform: "gitee", // 默认平台
				//TODO
				Operator: "", // 操作人
			}

			if err := db.InsertLFSObj(lfsObj); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				must(json.NewEncoder(w).Encode(batch.ErrorResponse{
					Message: "failed to insert metadata",
				}))
				return
			}
		}
	}

	must(json.NewEncoder(w).Encode(resp))
}

func (s *server) handleRequestObject(req batch.Request) batch.Response {
	var resp batch.Response
	for i := 0; i < len(req.Objects); i++ {
		in := req.Objects[i]
		resp.Objects = append(resp.Objects, batch.Object{
			OID:  in.OID,
			Size: in.Size,
		})
		out := &resp.Objects[len(resp.Objects)-1]

		if !oidRegexp.MatchString(in.OID) {
			out.Error = &batch.ObjectError{
				Code:    422,
				Message: "oid must be a SHA-256 hash in lower case hexadecimal",
			}
			continue
		}

		switch req.Operation {
		case "download":
			s.downloadObject(&in, out)
		case "upload":
			s.uploadObject(&in, out)
		default:
			continue
		}
	}
	return resp
}

func (s *server) dealWithAuthError(userInRepo auth.UserInRepo, w http.ResponseWriter, r *http.Request) error {
	var err error
	if username, password, ok := r.BasicAuth(); ok {
		userInRepo.Username = username
		userInRepo.Password = password

		if !validatecfg.usernameRegexp.MatchString(userInRepo.Username) ||
			!validatecfg.passwordRegexp.MatchString(userInRepo.Password) {
			w.WriteHeader(http.StatusBadRequest)
			must(json.NewEncoder(w).Encode(batch.ErrorResponse{
				Message: "invalid username or password format",
			}))
			return errors.New("invalid username or password format")
		}
		err = s.isAuthorized(userInRepo)
	} else if authToken := r.Header.Get("Authorization"); authToken != "" {
		err = auth.VerifySSHAuthToken(authToken, userInRepo)
	} else {
		err = errors.New("unauthorized: cannot get password")
	}
	if err != nil {
		v := err.Error()
		switch {
		case strings.HasPrefix(v, "unauthorized") || strings.HasPrefix(v, "not_found"):
			w.WriteHeader(401)
		case strings.HasPrefix(v, "forbidden"):
			w.WriteHeader(403)
		default:
			w.WriteHeader(500)
		}
		w.Header().Set("LFS-Authenticate", `Basic realm="Git LFS"`)
		must(json.NewEncoder(w).Encode(batch.ErrorResponse{
			Message: v,
		}))
		return err
	}

	return nil
}

func (s *server) downloadObject(in *batch.RequestObject, out *batch.Object) {
	if metadata, err := s.getObjectMetadataInput(s.key(in.OID)); err != nil {
		out.Error = &batch.ObjectError{
			Code:    404,
			Message: err.Error(),
		}
		return
	} else if in.Size != int(metadata.ContentLength) {
		out.Error = &batch.ObjectError{
			Code:    422,
			Message: "found object with wrong size",
		}
	} else {
		logrus.Infof("Metadata check pass, Size check pass")
	}
	getObjectInput := &obs.CreateSignedUrlInput{}
	getObjectInput.Method = obs.HttpMethodGet
	getObjectInput.Bucket = s.bucket
	getObjectInput.Key = s.key(in.OID)
	getObjectInput.Expires = int(s.ttl / time.Second)
	getObjectInput.Headers = map[string]string{contentType: "application/octet-stream"}
	// 生成下载对象的带授权信息的URL
	v := s.generateDownloadUrl(getObjectInput)

	out.Actions = &batch.Actions{
		Download: &batch.Action{
			HRef:      v.String(),
			Header:    getObjectInput.Headers,
			ExpiresIn: int(s.ttl / time.Second),
		},
	}
}

func (s *server) uploadObject(in *batch.RequestObject, out *batch.Object) {
	if out.Size > ObsPutLimit {
		out.Error = &batch.ObjectError{
			Code:    422,
			Message: "cannot upload objects larger than 5GB to S3 via LFS basic transfer adapter",
		}
		return
	}

	_, err := s.getObjectMetadataInput(s.key(in.OID))
	if err == nil {
		logrus.Infof("object already exists: %s", in.OID)
		return
	}

	putObjectInput := &obs.CreateSignedUrlInput{}
	putObjectInput.Method = obs.HttpMethodPut
	putObjectInput.Bucket = s.bucket
	putObjectInput.Key = s.key(in.OID)
	putObjectInput.Expires = int(s.ttl / time.Second)
	putObjectInput.Headers = map[string]string{contentType: "application/octet-stream"}
	putObjectOutput, err := s.client.CreateSignedUrl(putObjectInput)
	if err != nil {
		panic(err)
	}

	out.Actions = &batch.Actions{
		Upload: &batch.Action{
			HRef:      putObjectOutput.SignedUrl,
			Header:    putObjectInput.Headers,
			ExpiresIn: int(s.ttl / time.Second),
		},
	}
}

func (s *server) getObjectMetadataInput(key string) (output *obs.GetObjectMetadataOutput, err error) {
	getObjectMetadataInput := obs.GetObjectMetadataInput{
		Bucket: s.bucket,
		Key:    key,
	}
	return s.client.GetObjectMetadata(&getObjectMetadataInput)
}

// 生成下载对象的带授权信息的URL
func (s *server) generateDownloadUrl(getObjectInput *obs.CreateSignedUrlInput) *url.URL {
	// 生成下载对象的带授权信息的URL
	getObjectOutput, err := s.client.CreateSignedUrl(getObjectInput)
	if err != nil {
		panic(err)
	}
	v, err := url.Parse(getObjectOutput.SignedUrl)
	if err == nil {
		v.Host = s.cdnDomain
		v.Scheme = "https"
	} else {
		logrus.Infof("%s cannot be parsed", getObjectOutput.SignedUrl)
		panic(err)
	}
	return v
}

func (s *server) healthCheck(w http.ResponseWriter, r *http.Request) {
	response := batch.SuccessResponse{
		Message: "Success",
		Data:    "healthCheck success",
	}

	w.Header().Set(contentType, "application/json")
	w.WriteHeader(http.StatusOK)
	must(json.NewEncoder(w).Encode(response))
}

// --

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func (s *server) download(w http.ResponseWriter, r *http.Request) {
	oid := chi.URLParam(r, "oid")
	requestObject := &batch.RequestObject{
		OID: oid,
	}

	outputObject := &batch.Object{}

	if _, err := s.getObjectMetadataInput(s.key(requestObject.OID)); err != nil {
		outputObject.Error = &batch.ObjectError{
			Code:    404,
			Message: err.Error(),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(outputObject.Error)
		return
	}

	logrus.Infof("Metadata check pass")

	getObjectInput := &obs.CreateSignedUrlInput{
		Method:  obs.HttpMethodGet,
		Bucket:  s.bucket,
		Key:     s.key(requestObject.OID),
		Expires: int(s.ttl / time.Second),
		Headers: map[string]string{contentType: "application/octet-stream"},
	}

	v := s.generateDownloadUrl(getObjectInput)

	w.Header().Set("Content-Type", "application/json")

	response := map[string]string{"url": v.String()}

	w.WriteHeader(http.StatusOK)
	err := json.NewEncoder(w).Encode(response)
	if err != nil {
		return
	}
}

func (s *server) List(w http.ResponseWriter, r *http.Request) {
	owner := chi.URLParam(r, "owner")
	repo := chi.URLParam(r, "repo")
	platform := r.URL.Query().Get("platform")

	var files []db.LfsObj

	// 查询数据库
	if err := db.Db.Model(&db.LfsObj{}).Where("owner = ? AND repo = ? AND platform = ? AND exist = 1", owner, repo, platform).Find(&files).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 设置响应头为 JSON 格式
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	// 返回 JSON 格式的文件列表
	if err := json.NewEncoder(w).Encode(files); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
