package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_getParsedResponse(t *testing.T) {
	t.Run("200 response parses JSON into obj", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"full_name": "org/repo"})
		}))
		defer server.Close()

		var result map[string]string
		err := getParsedResponse("GET", server.URL, http.Header{}, nil, &result)
		assert.NoError(t, err)
		assert.Equal(t, "org/repo", result["full_name"])
	})

	t.Run("404 returns not_found error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		err := getParsedResponse("GET", server.URL, http.Header{}, nil, nil)
		assert.EqualError(t, err, "not_found")
	})

	t.Run("401 returns unauthorized error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer server.Close()

		err := getParsedResponse("GET", server.URL, http.Header{}, nil, nil)
		assert.EqualError(t, err, "unauthorized")
	})

	t.Run("403 returns forbidden error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		defer server.Close()

		err := getParsedResponse("GET", server.URL, http.Header{}, nil, nil)
		assert.EqualError(t, err, "forbidden")
	})

	t.Run("500 returns system_error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		err := getParsedResponse("GET", server.URL, http.Header{}, nil, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "system_error")
	})
}
