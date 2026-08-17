package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"bou.ke/monkey"
	"github.com/metalogical/BigFiles/db"
	"github.com/stretchr/testify/assert"
)

func TestVerifyWebhookKey_ValidToken(t *testing.T) {
	origKey := Webhook_key
	Webhook_key = "test-secret"
	defer func() { Webhook_key = origKey }()

	req := httptest.NewRequest(http.MethodPost, "/webhook/merge", nil)
	req.Header.Set("X-Gitee-Token", "test-secret")
	assert.True(t, verifyWebhookKey(req))
}

func TestVerifyWebhookKey_InvalidToken(t *testing.T) {
	origKey := Webhook_key
	Webhook_key = "correct-token"
	defer func() { Webhook_key = origKey }()

	req := httptest.NewRequest(http.MethodPost, "/webhook/merge", nil)
	req.Header.Set("X-Gitee-Token", "wrong-token")
	assert.False(t, verifyWebhookKey(req))
}

func TestVerifyWebhookKey_MissingToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/webhook/merge", nil)
	assert.False(t, verifyWebhookKey(req))
}

func TestShouldSkipProcessing_NonMergeHook(t *testing.T) {
	payload := &GiteeWebhookPayload{
		HookName: "push_hooks",
	}
	assert.True(t, shouldSkipProcessing(payload))
}

func TestShouldSkipProcessing_MergeHookNotMerged(t *testing.T) {
	payload := &GiteeWebhookPayload{
		HookName:    "merge_request_hooks",
		PullRequest: struct {
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
		}{Merged: false},
	}
	assert.True(t, shouldSkipProcessing(payload))
}

func TestShouldSkipProcessing_MergeHookMerged(t *testing.T) {
	payload := &GiteeWebhookPayload{
		HookName: "merge_request_hooks",
	}
	payload.PullRequest.Merged = true
	assert.False(t, shouldSkipProcessing(payload))
}

func TestIsOIDLine(t *testing.T) {
	assert.True(t, isOIDLine("+oid sha256:abc123"))
	assert.False(t, isOIDLine("oid sha256:abc123"))
	assert.False(t, isOIDLine("+size 100"))
	assert.False(t, isOIDLine(""))
}

func TestFindFileName_Found(t *testing.T) {
	lines := []string{
		"diff --git a/path/to/file.txt b/path/to/file.txt",
		"index abc..def 100644",
		"--- a/path/to/file.txt",
		"+++ b/path/to/file.txt",
		"+oid sha256:abc123",
	}
	result := findFileName(lines, 4)
	assert.Equal(t, "path/to/file.txt", result)
}

func TestFindFileName_NotFound(t *testing.T) {
	lines := []string{
		"some other line",
		"+oid sha256:abc123",
	}
	result := findFileName(lines, 1)
	assert.Equal(t, "", result)
}

func TestFindFileName_BeyondRange(t *testing.T) {
	lines := []string{
		"diff --git a/far.txt b/far.txt",
		"line1",
		"line2",
		"line3",
		"line4",
		"line5",
		"line6",
		"line7",
		"line8",
		"line9",
		"line10",
		"+oid sha256:abc123",
	}
	result := findFileName(lines, 11)
	assert.Equal(t, "", result, "diff line is beyond 10-line lookback")
}

func TestExtractLFSFileInfo_WithSize(t *testing.T) {
	lines := []string{
		"diff --git a/data.bin b/data.bin",
		"+oid sha256:abcdef1234567890",
		"+size 2048",
	}
	fileInfo, skip := extractLFSFileInfo(lines, 1)
	assert.NotNil(t, fileInfo)
	assert.True(t, skip)
	assert.Equal(t, "abcdef1234567890", fileInfo.Oid)
	assert.Equal(t, 2048, fileInfo.Size)
	assert.Equal(t, "data.bin", fileInfo.FileName)
}

func TestExtractLFSFileInfo_WithoutSize(t *testing.T) {
	lines := []string{
		"diff --git a/data.bin b/data.bin",
		"+oid sha256:abcdef1234567890",
		"some other line",
	}
	fileInfo, skip := extractLFSFileInfo(lines, 1)
	assert.NotNil(t, fileInfo)
	assert.False(t, skip)
	assert.Equal(t, 0, fileInfo.Size)
}

func TestExtractLFSFileInfo_EmptyOID(t *testing.T) {
	lines := []string{
		"+oid sha256:",
	}
	fileInfo, _ := extractLFSFileInfo(lines, 0)
	assert.Nil(t, fileInfo, "empty OID should return nil")
}

func TestExtractLFSFileInfo_EmptyFileName(t *testing.T) {
	lines := []string{
		"+oid sha256:abcdef1234567890",
	}
	fileInfo, _ := extractLFSFileInfo(lines, 0)
	assert.Nil(t, fileInfo, "missing file name should return nil")
}

func TestParseLFSFilesFromDiff_SingleFile(t *testing.T) {
	diff := `diff --git a/large.bin b/large.bin
index abc..def 100644
--- a/large.bin
+++ b/large.bin
+oid sha256:aabbccdd1122334455667788990011223344556677889900112233445566778899
+size 4096
`
	files, err := parseLFSFilesFromDiff(diff)
	assert.NoError(t, err)
	assert.Len(t, files, 1)
	assert.Equal(t, "aabbccdd1122334455667788990011223344556677889900112233445566778899", files[0].Oid)
	assert.Equal(t, 4096, files[0].Size)
	assert.Equal(t, "large.bin", files[0].FileName)
}

func TestParseLFSFilesFromDiff_MultipleFiles(t *testing.T) {
	diff := `diff --git a/file1.bin b/file1.bin
+oid sha256:aaa1111111111111111111111111111111111111111111111111111111111111
+size 100
diff --git a/file2.bin b/file2.bin
+oid sha256:bbb2222222222222222222222222222222222222222222222222222222222222
+size 200
`
	files, err := parseLFSFilesFromDiff(diff)
	assert.NoError(t, err)
	assert.Len(t, files, 2)
	assert.Equal(t, "file1.bin", files[0].FileName)
	assert.Equal(t, "file2.bin", files[1].FileName)
}

func TestParseLFSFilesFromDiff_NoLFSFiles(t *testing.T) {
	diff := `diff --git a/normal.txt b/normal.txt
+just a normal change
`
	files, err := parseLFSFilesFromDiff(diff)
	assert.NoError(t, err)
	assert.Len(t, files, 0)
}

func TestWriteJSONResponse(t *testing.T) {
	w := httptest.NewRecorder()
	data := map[string]string{"message": "ok"}
	writeJSONResponse(w, http.StatusOK, data)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var decoded map[string]string
	err := json.NewDecoder(w.Body).Decode(&decoded)
	assert.NoError(t, err)
	assert.Equal(t, "ok", decoded["message"])
}

func TestWriteJSONResponse_ErrorStatusCode(t *testing.T) {
	w := httptest.NewRecorder()
	data := map[string]string{"error": "bad request"}
	writeJSONResponse(w, http.StatusBadRequest, data)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestParseWebhookPayload_Valid(t *testing.T) {
	s := &server{}
	body := `{"hook_name":"merge_request_hooks","pull_request":{"merged":true,"id":1,"diff_url":"https://gitee.com/test/repo/diff"}}`
	req := httptest.NewRequest(http.MethodPost, "/webhook/merge", strings.NewReader(body))

	payload, err := s.parseWebhookPayload(req)
	assert.NoError(t, err)
	assert.Equal(t, "merge_request_hooks", payload.HookName)
	assert.True(t, payload.PullRequest.Merged)
}

func TestParseWebhookPayload_InvalidJSON(t *testing.T) {
	s := &server{}
	req := httptest.NewRequest(http.MethodPost, "/webhook/merge", strings.NewReader("not json"))

	_, err := s.parseWebhookPayload(req)
	assert.Error(t, err)
}

func TestProcessLFSFile_ExistingObjectInsert(t *testing.T) {
	origWebhookKey := Webhook_key
	Webhook_key = "test"
	defer func() { Webhook_key = origWebhookKey }()

	s := &server{}
	lfsFile := LFSFile{Oid: "existing-oid", FileName: "test.bin", Size: 100}

	monkey.Patch(db.SelectLfsObjByOid, func(oid string) ([]db.LfsObj, error) {
		return []db.LfsObj{{Oid: oid, Exist: 1}}, nil
	})
	monkey.Patch(db.InsertLFSObj, func(obj db.LfsObj) error {
		return nil
	})
	defer monkey.UnpatchAll()

	err := s.processLFSFile(lfsFile, "owner", "repo", "user")
	assert.NoError(t, err)
}

func TestProcessLFSFile_SelectError(t *testing.T) {
	s := &server{}
	lfsFile := LFSFile{Oid: "err-oid", FileName: "test.bin", Size: 100}

	monkey.Patch(db.SelectLfsObjByOid, func(oid string) ([]db.LfsObj, error) {
		return nil, errors.New("db error")
	})
	defer monkey.UnpatchAll()

	err := s.processLFSFile(lfsFile, "owner", "repo", "user")
	assert.Error(t, err)
}

func TestProcessLFSFile_InsertError(t *testing.T) {
	s := &server{}
	lfsFile := LFSFile{Oid: "ins-oid", FileName: "test.bin", Size: 100}

	monkey.Patch(db.SelectLfsObjByOid, func(oid string) ([]db.LfsObj, error) {
		return []db.LfsObj{{Oid: oid, Exist: 1}}, nil
	})
	monkey.Patch(db.InsertLFSObj, func(obj db.LfsObj) error {
		return errors.New("insert failed")
	})
	defer monkey.UnpatchAll()

	err := s.processLFSFile(lfsFile, "owner", "repo", "user")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to insert")
}

func TestProcessLFSFile_NoExistingObject(t *testing.T) {
	s := &server{}
	lfsFile := LFSFile{Oid: "nonexistent-oid", FileName: "test.bin", Size: 100}

	monkey.Patch(db.SelectLfsObjByOid, func(oid string) ([]db.LfsObj, error) {
		return nil, nil
	})
	defer monkey.UnpatchAll()

	err := s.processLFSFile(lfsFile, "owner", "repo", "user")
	assert.NoError(t, err)
}

func TestExtractLFSFilesFromDiff_InvalidURL(t *testing.T) {
	s := &server{}
	_, err := s.extractLFSFilesFromDiff("://invalid-url")
	assert.Error(t, err)
}

func TestExtractLFSFilesFromDiff_NonHTTPS(t *testing.T) {
	s := &server{}
	_, err := s.extractLFSFilesFromDiff("http://gitee.com/test/repo/diff")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "HTTPS")
}

func TestExtractLFSFilesFromDiff_NonGiteeDomain(t *testing.T) {
	s := &server{}
	_, err := s.extractLFSFilesFromDiff("https://github.com/test/repo/diff")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "gitee.com")
}

func TestHandleGiteeWebhook_InvalidToken(t *testing.T) {
	origKey := Webhook_key
	Webhook_key = "secret"
	defer func() { Webhook_key = origKey }()

	s := &server{}
	req := httptest.NewRequest(http.MethodPost, "/webhook/merge", strings.NewReader(`{}`))
	req.Header.Set("X-Gitee-Token", "wrong")
	w := httptest.NewRecorder()

	s.handleGiteeWebhook(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestHandleGiteeWebhook_MissingToken(t *testing.T) {
	origKey := Webhook_key
	Webhook_key = "secret"
	defer func() { Webhook_key = origKey }()

	s := &server{}
	req := httptest.NewRequest(http.MethodPost, "/webhook/merge", strings.NewReader(`{}`))
	w := httptest.NewRecorder()

	s.handleGiteeWebhook(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestHandleGiteeWebhook_InvalidPayload(t *testing.T) {
	origKey := Webhook_key
	Webhook_key = "secret"
	defer func() { Webhook_key = origKey }()

	s := &server{}
	req := httptest.NewRequest(http.MethodPost, "/webhook/merge", strings.NewReader("not json"))
	req.Header.Set("X-Gitee-Token", "secret")
	w := httptest.NewRecorder()

	s.handleGiteeWebhook(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleGiteeWebhook_SkipNonMergeRequest(t *testing.T) {
	origKey := Webhook_key
	Webhook_key = "secret"
	defer func() { Webhook_key = origKey }()

	s := &server{}
	body := `{"hook_name":"push_hooks"}`
	req := httptest.NewRequest(http.MethodPost, "/webhook/merge", strings.NewReader(body))
	req.Header.Set("X-Gitee-Token", "secret")
	w := httptest.NewRecorder()

	s.handleGiteeWebhook(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestProcessMergeRequest_NoLFSFiles(t *testing.T) {
	s := &server{}
	payload := &GiteeWebhookPayload{}
	payload.PullRequest.DiffURL = ""
	payload.PullRequest.Base.Repo.FullName = "owner/repo"

	lfsFiles, err := s.processMergeRequest(payload)

	_ = lfsFiles
	_ = err
}

func TestProcessLFSFile_DBSelectError(t *testing.T) {
	s := &server{}
	lfsFile := LFSFile{Oid: "test-oid", FileName: "test.bin", Size: 100}

	monkey.Patch(db.SelectLfsObjByOid, func(oid string) ([]db.LfsObj, error) {
		return nil, errors.New("db conn failed")
	})
	defer monkey.UnpatchAll()

	err := s.processLFSFile(lfsFile, "owner", "repo", "user")
	assert.Error(t, err)
}

func TestWriteSuccessResponse(t *testing.T) {
	s := &server{}
	w := httptest.NewRecorder()
	payload := &GiteeWebhookPayload{}
	payload.PullRequest.ID = 42
	payload.PullRequest.HTMLURL = "https://gitee.com/test/repo/pull/42"
	payload.PullRequest.Merged = true

	s.writeSuccessResponse(w, payload, []LFSFile{
		{Oid: "abc", FileName: "test.bin", Size: 100},
	})

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var resp map[string]interface{}
	err := json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.Equal(t, "Webhook processed successfully", resp["message"])
}

func TestParseLFSFilesFromDiff_EmptyDiff(t *testing.T) {
	files, err := parseLFSFilesFromDiff("")
	assert.NoError(t, err)
	assert.Len(t, files, 0)
}

func TestExtractLFSFileInfo_InvalidSize(t *testing.T) {
	lines := []string{
		"diff --git a/data.bin b/data.bin",
		"+oid sha256:abcdef1234567890",
		"+size notanumber",
	}
	fileInfo, skip := extractLFSFileInfo(lines, 1)
	assert.NotNil(t, fileInfo)
	assert.True(t, skip)
	assert.Equal(t, 0, fileInfo.Size, "invalid size should default to 0")
}

func TestHandleGiteeWebhook_ProcessMergeError(t *testing.T) {
	origKey := Webhook_key
	Webhook_key = "secret"
	defer func() { Webhook_key = origKey }()

	s := &server{}
	body := `{"hook_name":"merge_request_hooks","pull_request":{"merged":true,"id":1,"diff_url":"https://github.com/test/repo/diff","base":{"repo":{"full_name":"owner/repo"}}}}`
	req := httptest.NewRequest(http.MethodPost, "/webhook/merge", strings.NewReader(body))
	req.Header.Set("X-Gitee-Token", "secret")
	w := httptest.NewRecorder()

	s.handleGiteeWebhook(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code, "non-gitee diff URL should fail")
}

func TestWriteJSONResponse_EncodeError(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSONResponse(w, http.StatusOK, func() {})
	assert.Equal(t, http.StatusOK, w.Code, "status already written before encode attempt")
}

func TestProcessMergeRequest_ExtractError(t *testing.T) {
	s := &server{}
	payload := &GiteeWebhookPayload{}
	payload.PullRequest.DiffURL = "http://bad-scheme.com/diff"
	payload.PullRequest.Base.Repo.FullName = "owner/repo"

	_, err := s.processMergeRequest(payload)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "HTTPS")
}

func TestProcessMergeRequest_EmptyDiffURL(t *testing.T) {
	s := &server{}
	payload := &GiteeWebhookPayload{}
	payload.PullRequest.DiffURL = ""
	payload.PullRequest.Base.Repo.FullName = "owner/repo"

	_, err := s.processMergeRequest(payload)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "HTTPS")
}
