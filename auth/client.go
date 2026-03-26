package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

type Client struct {
}

// getParsedResponse gets response data from gitee
func getParsedResponse(method, path string, header http.Header, body io.Reader, obj interface{}) error {
	client := &http.Client{
		Timeout: 30 * time.Second, // 整个请求的最大超时时间
	}
	req, err := http.NewRequest(method, path, body)
	if err != nil {
		panic(err)
	}
	req.Header = header
	response, err := client.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("请求超时: %w", err)
		}
		return fmt.Errorf("请求执行失败: %w", err)
	}
	defer response.Body.Close()

	if splitPath := strings.Split(path, "?"); len(splitPath) != 1 {
		logrus.Infof("query %s with token | %d", splitPath[0], response.StatusCode)
	} else {
		logrus.Infof("query %s without token | %d", splitPath[0], response.StatusCode)
	}

	if response.StatusCode/100 != 2 {
		if response.StatusCode == http.StatusNotFound {
			return errors.New("not_found")
		} else if response.StatusCode == http.StatusUnauthorized {
			return errors.New("unauthorized")
		} else if response.StatusCode == http.StatusForbidden {
			return errors.New("forbidden")
		}
		return fmt.Errorf("system_error: %v", response.StatusCode)
	}
	data, err := io.ReadAll(response.Body)
	if err != nil {
		panic(err)
	}
	err = json.Unmarshal(data, &obj)
	if err != nil {
		panic(err)
	}
	return nil
}
