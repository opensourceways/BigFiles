package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type Client struct {
}

// getParsedResponse gets response data from gitee
func getParsedResponse(method, path string, header http.Header, body io.Reader, obj interface{}) error {
	req, err := http.NewRequest(method, path, body)
	if err != nil {
		panic(err)
	}
	req.Header = header
	fmt.Println(strings.Split(path, "?")[0])
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	defer response.Body.Close()
	if response.StatusCode/100 != 2 {
		if response.StatusCode == http.StatusNotFound {
			return errors.New("repository not found")
		} else if response.StatusCode == http.StatusUnauthorized {
			return errors.New("unauthorized")
		}
		return errors.New("error occured accessing gitee")
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
