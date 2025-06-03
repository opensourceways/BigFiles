package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/metalogical/BigFiles/db"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var diffcheck = "+size "

func (s *server) handleGiteeWebhook(w http.ResponseWriter, r *http.Request) {
	if !verifyWebhookKey(r) {
		logrus.Errorf("Invalid Gitee token")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	payload, err := s.parseWebhookPayload(r)
	if err != nil {
		logrus.Errorf("Failed to decode webhook payload: %v", err)
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	if shouldSkipProcessing(payload) {
		writeJSONResponse(w, http.StatusOK, map[string]string{"message": "Skipped non-merge request"})
		return
	}

	lfsFiles, err := s.processMergeRequest(payload)
	if err != nil {
		logrus.Errorf("Failed to process merge request: %v", err)
		http.Error(w, "Failed to process request", http.StatusInternalServerError)
		return
	}

	s.writeSuccessResponse(w, payload, lfsFiles)
}

// verifyWebhookKey 验证 Gitee Webhook 的 Token
func verifyWebhookKey(r *http.Request) bool {
	// 从 Header 中获取 token
	receivedToken := r.Header.Get("X-Gitee-Token")
	if receivedToken == "" {
		logrus.Warn("Missing X-Gitee-Token in header")
		return false
	}
	return receivedToken == Webhook_key
}

// parseWebhookPayload 解析webhook请求体
func (s *server) parseWebhookPayload(r *http.Request) (*GiteeWebhookPayload, error) {
	var payload GiteeWebhookPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		return nil, err
	}
	return &payload, nil
}

// shouldSkipProcessing 判断是否应该跳过处理
func shouldSkipProcessing(payload *GiteeWebhookPayload) bool {
	return payload.HookName != "merge_request_hooks" || !payload.PullRequest.Merged
}

// processMergeRequest 处理合并请求的核心逻辑
func (s *server) processMergeRequest(payload *GiteeWebhookPayload) ([]LFSFile, error) {
	lfsFiles, err := s.extractLFSFilesFromDiff(payload.PullRequest.DiffURL)
	if err != nil {
		return nil, fmt.Errorf("failed to check diff for LFS files: %w", err)
	}

	if len(lfsFiles) == 0 {
		return nil, nil
	}

	repoOwner, repoName, _ := strings.Cut(payload.PullRequest.Base.Repo.FullName, "/")
	operator := payload.PullRequest.User.Login

	for _, lfsFile := range lfsFiles {
		if err := s.processLFSFile(lfsFile, repoOwner, repoName, operator); err != nil {
			return nil, err
		}
	}

	return lfsFiles, nil
}

// processLFSFile 处理单个LFS文件
func (s *server) processLFSFile(lfsFile LFSFile, repoOwner, repoName, operator string) error {
	existingObj, err := db.SelectLfsObjByOid(lfsFile.Oid)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return fmt.Errorf("failed to query LFS object by OID: %w", err)
	}

	if existingObj == nil {
		logrus.Infof("LFS object with OID %s not exists, skipping", lfsFile.Oid)
		return nil
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

	if err := db.InsertLFSObj(obj); err != nil {
		return fmt.Errorf("failed to insert LFS object: %w", err)
	}

	return nil
}

// writeSuccessResponse 写入成功响应
func (s *server) writeSuccessResponse(w http.ResponseWriter, payload *GiteeWebhookPayload, lfsFiles []LFSFile) {
	response := map[string]interface{}{
		"message":          "Webhook processed successfully",
		"lfs_files_count":  len(lfsFiles),
		"pull_request_id":  payload.PullRequest.ID,
		"pull_request_url": payload.PullRequest.HTMLURL,
		"merged":           payload.PullRequest.Merged,
	}
	writeJSONResponse(w, http.StatusOK, response)
}

// GiteeWebhookPayload 定义webhook负载结构
type GiteeWebhookPayload struct {
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
		Base struct {
			Ref  string `json:"ref"`
			Sha  string `json:"sha"`
			Repo struct {
				FullName string `json:"full_name"`
				Owner    struct {
					Login string `json:"login"`
				} `json:"owner"`
				Name string `json:"name"`
			} `json:"repo"`
		} `json:"base"`
	} `json:"pull_request"`
}

// LFSFile 表示从diff中提取的LFS文件信息
type LFSFile struct {
	Oid      string `json:"oid"`
	FileName string `json:"file_name"`
	Size     int    `json:"size"`
}

// extractLFSFilesFromDiff 从diff中提取LFS文件信息
func (s *server) extractLFSFilesFromDiff(diffURL string) ([]LFSFile, error) {
	parsedURL, err := url.Parse(diffURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL format: %w", err)
	}

	if parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("only HTTPS protocol is allowed")
	}

	hostname := parsedURL.Hostname()
	if !strings.HasSuffix(hostname, ".gitee.com") && hostname != "gitee.com" {
		return nil, fmt.Errorf("only gitee.com domains are permitted")
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
		},
	}

	resp, err := client.Get(diffURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch diff: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	diff, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read diff: %w", err)
	}

	return parseLFSFilesFromDiff(string(diff))
}

// parseLFSFilesFromDiff 从diff内容中解析LFS文件信息
func parseLFSFilesFromDiff(diffContent string) ([]LFSFile, error) {
	var lfsFiles []LFSFile
	lines := strings.Split(diffContent, "\n")

	for i := 0; i < len(lines); i++ {
		if !isOIDLine(lines[i]) {
			continue
		}

		fileInfo, skip := extractLFSFileInfo(lines, i)
		if fileInfo != nil {
			lfsFiles = append(lfsFiles, *fileInfo)
		}
		if skip {
			i++ // 跳过已处理的size行
		}
	}

	return lfsFiles, nil
}

// extractLFSFileInfo 从指定位置提取LFS文件信息
func extractLFSFileInfo(lines []string, currentIdx int) (*LFSFile, bool) {
	// 提取OID
	oid := strings.TrimPrefix(lines[currentIdx], "+oid sha256:")

	// 提取Size
	size, skip := 0, false
	if currentIdx+1 < len(lines) && strings.HasPrefix(lines[currentIdx+1], diffcheck) {
		sizeStr := strings.TrimPrefix(lines[currentIdx+1], diffcheck)
		size, _ = strconv.Atoi(sizeStr)
		skip = true
	}

	// 提取文件名
	fileName := findFileName(lines, currentIdx)

	if oid != "" && fileName != "" {
		return &LFSFile{
			Oid:      oid,
			FileName: fileName,
			Size:     size,
		}, skip
	}

	return nil, skip
}

// isOIDLine 判断是否是OID行
func isOIDLine(line string) bool {
	return strings.HasPrefix(line, "+oid sha256:")
}

// findFileName 向上查找文件名
func findFileName(lines []string, currentIdx int) string {
	for j := currentIdx; j >= 0 && j >= currentIdx-10; j-- {
		if strings.HasPrefix(lines[j], "diff --git a/") {
			parts := strings.SplitN(lines[j][len("diff --git a/"):], " ", 2)
			if len(parts) > 0 {
				return parts[0]
			}
		}
	}
	return ""
}

// writeJSONResponse 辅助函数
func writeJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Failed to encode JSON response: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}
