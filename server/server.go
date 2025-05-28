package server

import (
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"encoding/json"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"net/http"
	"net/url"

	"github.com/go-chi/chi"
	"github.com/huaweicloud/huaweicloud-sdk-go-obs/obs"
	"github.com/metalogical/BigFiles/auth"
	"github.com/metalogical/BigFiles/batch"
	"github.com/metalogical/BigFiles/db"
)

var ObsPutLimit int = 5*int(math.Pow10(9)) - 1 // 5GB - 1
var oidRegexp = regexp.MustCompile("^[a-f0-9]{64}$")
var contentType = "Content-Type"
var jsonHeader = "application/json"
var obsHeader = "application/octet-stream"

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
	r.Get("/{owner}/{repo}/object/list", s.List)
	r.Post("/{owner}/{repo}/delete/{oid}", s.delete)
	r.Get("/info/lfs/objects/{oid}", s.download)
	r.Get("/repos/list", s.listAllRepos)
	r.Get("/oid/filename", checkOid)
	r.Post("/webhook/merge", s.handleGiteeWebhook)
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

	if _, err = auth.CheckRepoOwner(userInRepo); req.Operation == "upload" || err != nil {
		err := s.dealWithAuthError(userInRepo, w, r)
		if err != nil {
			return
		}
	}

	resp := s.handleRequestObject(req)

	// 添加元数据
	addMetaData(req, w, userInRepo)

	must(json.NewEncoder(w).Encode(resp))
}

func addMetaData(req batch.Request, w http.ResponseWriter, userInRepo auth.UserInRepo) {
	// 添加元数据
	if req.Operation == "upload" {
		for _, object := range req.Objects {
			lfsObj := db.LfsObj{
				Repo:     userInRepo.Repo,
				Owner:    userInRepo.Owner,
				Oid:      object.OID,
				Size:     object.Size,
				Exist:    2,                   // 默认设置为2
				Platform: "gitee",             // 默认平台
				Operator: userInRepo.Username, // 操作人
			}

			if err := db.InsertLFSObj(lfsObj); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				must(json.NewEncoder(w).Encode(batch.ErrorResponse{
					Message: "failed to insert metadata",
				}))
				return
			}
			logrus.Infof("insert lfsobj succeed")
		}
		// 10分钟后异步执行，带错误恢复
		time.AfterFunc(10*time.Minute, func() {
			defer func() {
				if err := recover(); err != nil {
					logrus.Errorf("checkRepoOidName panic: %v", err)
				}
			}()
			checkRepoOidName(userInRepo)
		})
	}
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
	//lfsObjs, err := db.SelectLfsObjByOid(in.OID)
	//if err != nil || len(lfsObjs) == 0 {
	//	logrus.Infof("cant find object by oid, oid : %s", in.OID)
	//	out.Error = &batch.ObjectError{
	//		Code:    404,
	//		Message: "object not found",
	//	}
	//	return
	//}
	//if lfsObjs[0].Exist == 0 {
	//	logrus.Infof("lfs object not exist, oid : %s", in.OID)
	//	out.Error = &batch.ObjectError{
	//		Code:    404,
	//		Message: "object has been deleted",
	//	}
	//	return
	//}
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
	getObjectInput.Headers = map[string]string{contentType: obsHeader}
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
	putObjectInput.Headers = map[string]string{contentType: obsHeader}
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

	w.Header().Set(contentType, jsonHeader)
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
		w.Header().Set(contentType, jsonHeader)
		w.WriteHeader(http.StatusNotFound)
		if err := json.NewEncoder(w).Encode(outputObject.Error); err != nil {
			logrus.Errorf("failed to encode error response: %v", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		return
	}

	getObjectInput := &obs.CreateSignedUrlInput{
		Method:  obs.HttpMethodGet,
		Bucket:  s.bucket,
		Key:     s.key(requestObject.OID),
		Expires: int(s.ttl / time.Second),
		Headers: map[string]string{contentType: obsHeader},
	}

	v := s.generateDownloadUrl(getObjectInput)

	w.Header().Set(contentType, jsonHeader)

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

	page, limit := parsePaginationParams(r)

	files, err := s.getLfsFiles(owner, repo, platform, page, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	total, err := s.countLfsFiles(owner, repo, platform)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resp := s.buildListResponse(files, total)
	w.Header().Set(contentType, jsonHeader)
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func parsePaginationParams(r *http.Request) (int, int) {
	page := 1
	limit := 10

	if pageStr := r.URL.Query().Get("page"); pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	return page, limit
}

func (s *server) getLfsFiles(owner, repo, platform string, page, limit int) ([]db.LfsObj, error) {
	var files []db.LfsObj

	query := db.Db.Model(&db.LfsObj{}).
		Where("owner = ? AND repo = ? AND platform = ? AND exist = 1", owner, repo, platform).
		Order("create_time DESC").
		Limit(limit).
		Offset((page - 1) * limit)

	if err := query.Find(&files).Error; err != nil {
		return nil, err
	}
	return files, nil
}

func (s *server) countLfsFiles(owner, repo, platform string) (int64, error) {
	var total int64
	if err := db.Db.Model(&db.LfsObj{}).
		Where("owner = ? AND repo = ? AND platform = ? AND exist = 1", owner, repo, platform).
		Count(&total).Error; err != nil {
		return 0, err
	}
	return total, nil
}

type FileResponse struct {
	Owner      string `json:"owner"`
	Repo       string `json:"repo"`
	Size       int    `json:"size"`
	Oid        string `json:"oid"`
	FileName   string `json:"file_name"`
	CreateTime int64  `json:"create_time"`
	UpdateTime int64  `json:"update_time"`
}

func (s *server) buildListResponse(files []db.LfsObj, total int64) interface{} {
	response := make([]FileResponse, len(files))
	for i, file := range files {
		response[i] = FileResponse{
			Owner:      file.Owner,
			Repo:       file.Repo,
			Size:       file.Size,
			Oid:        file.Oid,
			FileName:   file.FileName,
			CreateTime: file.CreateTime.Unix(),
			UpdateTime: file.UpdateTime.Unix(),
		}
	}

	return struct {
		Total int            `json:"total"`
		Files []FileResponse `json:"files"`
	}{
		Total: int(total),
		Files: response,
	}
}

func (s *server) listAllRepos(w http.ResponseWriter, r *http.Request) {
	searchKey, page, limit := s.getQueryParams(r)

	repoList, total, err := fetchRepoList(searchKey, page, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := s.buildListAllReposResponse(total, repoList)

	w.Header().Set(contentType, jsonHeader)
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
func checkOid(w http.ResponseWriter, r *http.Request) {
	checkOidFileName()
}

func checkOidFileName() {
	repoList, _, err := fetchRepoList("", 0, 0)
	if err != nil {
		logrus.Errorf("fetch repo list failed: %v", err)
		return
	}
	for _, repo := range repoList {
		userInRepo := auth.UserInRepo{
			Repo:  repo.Repo,
			Owner: repo.Owner}
		logrus.Infof("checkOidFileName owner:%v repo:%v", repo.Owner, repo.Repo)
		checkRepoOidName(userInRepo)

	}

}

func checkRepoOidName(userInRepo auth.UserInRepo) (oidFileNameMap map[string]auth.FileInfo) {
	oidFileNameMap, err := auth.GetLFSMapping(userInRepo)
	if err != nil {
		logrus.Errorf("get lfs mapping failed: %v", err)
	}
	checkOidFileNameMap(oidFileNameMap, userInRepo)
	if strings.ToLower(userInRepo.Owner) != "src-openeuler" {
		logrus.Infof("after check owner:%v repo:%v, check src-openeuler", userInRepo.Owner, userInRepo.Repo)
		repo, err := auth.CheckRepoOwner(userInRepo)
		if err != nil {
			return nil
		}
		if repo.Parent.Fullname != "" {
			userInRepo.Owner = strings.Split(repo.Parent.Fullname, "/")[0]
			userInRepo.Repo = strings.Split(repo.Parent.Fullname, "/")[1]
			return checkRepoOidName(userInRepo)
		}
	}
	return oidFileNameMap
}

func checkOidFileNameMap(oidFileNameMap map[string]auth.FileInfo, userInRepo auth.UserInRepo) {
	if oidFileNameMap == nil {
		return
	}
	for oid, fileInfo := range oidFileNameMap {
		lfsObjs, err := db.SelectLfsObjByOid(oid)
		if err != nil {
			logrus.Errorf("get lfs obj by oid failed: %v", err)
			continue
		}

		if len(lfsObjs) == 0 {
			logrus.Infof("oid:%v not exist, create", oid)
			lfsObj := db.LfsObj{
				Repo:     userInRepo.Repo,
				Owner:    userInRepo.Owner,
				Oid:      oid,
				Size:     int(fileInfo.Size),
				FileName: fileInfo.Name,
				Exist:    2,
				Platform: "gitee",
				Operator: "",
			}
			if err = db.InsertLFSObj(lfsObj); err != nil {
				logrus.Errorf("insert lfs obj failed: %v", err)
			}
			continue
		}

		// 检查对应oid文件在对应仓库下是否存在，如果不存在则创建对应数据
		checkLfsObjsInfo(oid, lfsObjs, fileInfo, userInRepo)
	}
}

func checkLfsObjsInfo(oid string, lfsObjs []db.LfsObj, fileInfo auth.FileInfo, userInRepo auth.UserInRepo) {
	exist := false
	logrus.Infof("check oid:%v info", oid)
	for _, lfsObj := range lfsObjs {
		if lfsObj.Owner == userInRepo.Owner {
			exist = true
		}

		if "" == lfsObj.FileName {
			err := db.UpdateLFSObjFileName(oid, fileInfo.Name, "")
			if err != nil {
				logrus.Errorf("update file name failed: %v", err)
				return
			}
		}
	}

	if !exist {
		lfsObj := db.LfsObj{
			Repo:     userInRepo.Repo,
			Owner:    userInRepo.Owner,
			Oid:      oid,
			Size:     int(fileInfo.Size),
			FileName: fileInfo.Name,
			Exist:    2,
			Platform: "gitee",
			Operator: "",
		}
		if err := db.InsertLFSObj(lfsObj); err != nil {
			logrus.Errorf("insert not exist lfs obj failed: %v", err)
		}
	}
}

func (s *server) getQueryParams(r *http.Request) (string, int, int) {
	searchKey := r.URL.Query().Get("searchKey")
	page := 1
	limit := 0

	if pageStr := r.URL.Query().Get("page"); pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	return searchKey, page, limit
}

func fetchRepoList(searchKey string, page, limit int) ([]struct {
	Owner         string    `json:"owner"`
	Repo          string    `json:"repo"`
	TotalSize     int       `json:"total_size"`
	Time          int64     `json:"time"`
	FirstFileTime time.Time `json:"first_file_time"`
}, int64, error) {
	var repoList []struct {
		Owner         string    `json:"owner"`
		Repo          string    `json:"repo"`
		TotalSize     int       `json:"total_size"`
		Time          int64     `json:"time"`
		FirstFileTime time.Time `json:"first_file_time"`
	}

	query := db.Db.Model(&db.LfsObj{}).
		Select("owner, repo, " +
			"SUM(CASE WHEN exist = 1 THEN size ELSE 0 END) AS total_size, " +
			"MIN(create_time) AS first_file_time").
		Group("owner, repo").
		Having("SUM(CASE WHEN exist = 1 THEN size ELSE 0 END) > 0")

	if searchKey != "" {
		query = applySearchFilter(query, searchKey)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// 按 first_file_time 降序排列
	query = query.Order("first_file_time DESC")

	if limit > 0 {
		query = query.Limit(limit).Offset((page - 1) * limit)
	}

	if err := query.Scan(&repoList).Error; err != nil {
		return nil, 0, err
	}

	for i, r := range repoList {
		repoList[i].Time = r.FirstFileTime.Unix()
	}

	return repoList, total, nil
}

func applySearchFilter(query *gorm.DB, searchKey string) *gorm.DB {
	parts := strings.SplitN(searchKey, "/", 2)
	if len(parts) == 2 {
		owner := parts[0]
		repo := parts[1]
		return query.Where("owner LIKE ? AND repo LIKE ?", "%"+owner+"%", "%"+repo+"%")
	}
	return query.Where("owner LIKE ? OR repo LIKE ?", "%"+searchKey+"%", "%"+searchKey+"%")
}

func (s *server) buildListAllReposResponse(total int64, repoList []struct {
	Owner         string    `json:"owner"`
	Repo          string    `json:"repo"`
	TotalSize     int       `json:"total_size"`
	Time          int64     `json:"time"`
	FirstFileTime time.Time `json:"first_file_time"`
}) interface{} {
	return struct {
		Total int `json:"total"`
		Repos []struct {
			Owner         string    `json:"owner"`
			Repo          string    `json:"repo"`
			TotalSize     int       `json:"total_size"`
			Time          int64     `json:"time"`
			FirstFileTime time.Time `json:"first_file_time"`
		} `json:"repos"`
	}{
		Total: int(total),
		Repos: repoList,
	}
}

func (s *server) delete(w http.ResponseWriter, r *http.Request) {
	// 获取路径参数
	owner := chi.URLParam(r, "owner")
	repo := chi.URLParam(r, "repo")
	oid := chi.URLParam(r, "oid")

	ygCookie, err := r.Cookie("_Y_G_")
	if err != nil {
		log.Printf("Cookie 'yg' not found: %v", err)
	} else {
		log.Printf("Cookie 'yg': %s", ygCookie.Value)
	}

	utCookie, err := r.Cookie("_U_T_")
	if err != nil {
		log.Printf("Cookie 'ut' not found: %v", err)
	} else {
		log.Printf("Cookie 'ut': %s", utCookie.Value)
	}

	userInRepo := auth.UserInRepo{Repo: repo, Owner: owner, Operation: "delete"}
	userInfo, _ := auth.GetOpenEulerUserInfo(utCookie.Value, ygCookie.Value, userInRepo)
	fmt.Println(userInfo)

	err = auth.VerifyUser(userInfo)
	if err != nil {
		// 记录认证失败日志信息
		logrus.Errorf("User permission verification failed for user %s in repo %s/%s: %v",
			userInfo.Username, userInfo.Owner, userInfo.Repo, err)

		http.Error(w, "Permission verification failed", http.StatusForbidden)
		return
	}

	// 获取删除人信息
	deletedBy := userInfo.Username

	// 检查记录是否存在
	var obj db.LfsObj
	if err := db.DB().Where("oid = ? AND owner = ? AND repo = ?", oid, owner, repo).First(&obj).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			http.Error(w, "Object not found", http.StatusNotFound)
		} else {
			log.Printf("Error retrieving object with ID %s from repo %s of owner %s: %v", oid, repo, owner, err)
			http.Error(w, "Failed to retrieve object", http.StatusInternalServerError)
		}
		return
	}

	// 更新记录，将 exist 字段设置为 0，并记录删除人
	if err := db.DB().Model(&obj).Updates(map[string]interface{}{
		"exist":    0,
		"Operator": deletedBy,
	}).Error; err != nil {
		log.Printf("Error marking object with ID %s as deleted in repo %s of owner %s: %v", oid, repo, owner, err)
		http.Error(w, "Failed to mark object as deleted", http.StatusInternalServerError)
		return
	}

	// 返回响应
	response := map[string]string{"message": "Object marked as deleted successfully"}
	w.Header().Set(contentType, jsonHeader)
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (s *server) handleGiteeWebhook(w http.ResponseWriter, r *http.Request) {
	// 1. 解析请求体
	var payload struct {
		HookName    string `json:"hook_name"`
		PullRequest struct {
			ID        int    `json:"id"`
			Number    int    `json:"number"`
			State     string `json:"state"`
			Title     string `json:"title"`
			HTMLURL   string `json:"html_url"`
			DiffURL   string `json:"diff_url"`
			Merged    bool   `json:"merged"`
			MergedAt  string `json:"merged_at"`
			CreatedAt string `json:"created_at"`
			User      struct {
				Login string `json:"login"`
			} `json:"user"`
			Head struct {
				Ref  string `json:"ref"`
				Sha  string `json:"sha"`
				Repo struct {
					FullName string `json:"full_name"`
					Owner    struct {
						Login string `json:"login"`
					} `json:"owner"`
					Name string `json:"name"`
				} `json:"repo"`
			} `json:"head"`
		} `json:"pull_request"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		logrus.Errorf("Failed to decode webhook payload: %v", err)
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}
	fmt.Println("-----", "payload.HookName:", payload.HookName)
	// 2. 检查是否为合并请求
	if payload.HookName != "merge_request_hooks" {
		logrus.Infof("Not a merge request hook, skipping. HookName: %s", payload.HookName)
		writeJSONResponse(w, http.StatusOK, map[string]string{"message": "Not a merge request, skipping"})
		return
	}

	// 3. 检查是否已合并
	fmt.Println("-----", "payload.PullRequest.Merged:", payload.PullRequest.Merged)
	if !payload.PullRequest.Merged {
		logrus.Infof("Pull request not merged, skipping. PR ID: %d", payload.PullRequest.ID)
		writeJSONResponse(w, http.StatusOK, map[string]string{"message": "Pull request not merged, skipping"})
		return
	}

	// 4. 获取 diff 内容并检查 LFS 文件
	lfsFiles, err := s.extractLFSFilesFromDiff(payload.PullRequest.DiffURL)
	if err != nil {
		logrus.Errorf("Failed to check diff for LFS files: %v", err)
		http.Error(w, "Failed to check diff", http.StatusInternalServerError)
		return
	}

	// 5. 如果存在LFS文件，写入数据库
	if len(lfsFiles) > 0 {
		fmt.Println("begin----------")
		repoOwner, repoName, _ := strings.Cut(payload.PullRequest.Head.Repo.FullName, "/")
		operator := payload.PullRequest.User.Login

		for _, lfsFile := range lfsFiles {
			existingObj, err := db.SelectLfsObjByOid(lfsFile.Oid)
			fmt.Println("search----------", existingObj)

			if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
				logrus.Errorf("Failed to query LFS object by OID: %v", err)
				http.Error(w, "Failed to check LFS object existence", http.StatusInternalServerError)
			}
			if existingObj == nil {
				logrus.Infof("LFS object with OID %s not exists, skipping insert", lfsFile.Oid)
				continue
			}
			obj := db.LfsObj{
				Oid:      lfsFile.Oid,
				FileName: lfsFile.FileName,
				Size:     lfsFile.Size,
				Platform: "gitee",
				Owner:    repoOwner,
				Repo:     repoName,
				Operator: operator,
				Exist:    2,
			}
			fmt.Println("insert----------", obj)

			if err := db.InsertLFSObj(obj); err != nil {
				logrus.Errorf("Failed to insert LFS object: %v", err)
				http.Error(w, "Failed to store LFS metadata", http.StatusInternalServerError)
				return
			}
		}
	}

	// 6. 返回响应
	response := map[string]interface{}{
		"message":          "Webhook processed successfully",
		"lfs_files_count":  len(lfsFiles),
		"pull_request_id":  payload.PullRequest.ID,
		"pull_request_url": payload.PullRequest.HTMLURL,
		"merged":           payload.PullRequest.Merged,
	}
	writeJSONResponse(w, http.StatusOK, response)
}

// LFSFile 表示从diff中提取的LFS文件信息
type LFSFile struct {
	Oid      string `json:"oid"`
	FileName string `json:"file_name"`
	Size     int    `json:"size"`
}

// extractLFSFilesFromDiff 从diff中提取LFS文件信息
func (s *server) extractLFSFilesFromDiff(diffURL string) ([]LFSFile, error) {
	resp, err := http.Get(diffURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch diff: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	diff, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read diff: %v", err)
	}

	return parseLFSFilesFromDiff(string(diff))
}

func parseLFSFilesFromDiff(diffContent string) ([]LFSFile, error) {
	var lfsFiles []LFSFile
	lines := strings.Split(diffContent, "\n")

	for i := 0; i < len(lines); i++ {
		// 直接查找 +oid sha256: 行
		if !strings.HasPrefix(lines[i], "+oid sha256:") {
			continue
		}

		var (
			oid      string
			fileName string
			size     int
		)

		// 提取OID
		oid = strings.TrimPrefix(lines[i], "+oid sha256:")

		// 提取Size（检查下一行是否是 +size）
		if i+1 < len(lines) && strings.HasPrefix(lines[i+1], "+size ") {
			sizeStr := strings.TrimPrefix(lines[i+1], "+size ")
			size, _ = strconv.Atoi(sizeStr)
		}

		// 提取文件名 - 向上查找最近的 diff --git a/ 行
		for j := i; j >= 0 && j >= i-10; j-- {
			if strings.HasPrefix(lines[j], "diff --git a/") {
				parts := strings.SplitN(lines[j][len("diff --git a/"):], " ", 2)
				if len(parts) > 0 {
					fileName = parts[0]
					break
				}
			}
		}

		if oid != "" && fileName != "" {
			lfsFiles = append(lfsFiles, LFSFile{
				Oid:      oid,
				FileName: fileName,
				Size:     size,
			})
		}

		// 跳过已处理的size行（如果存在）
		if i+1 < len(lines) && strings.HasPrefix(lines[i+1], "+size ") {
			i++
		}
	}

	return lfsFiles, nil
}

// writeJSONResponse 辅助函数
func writeJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}
