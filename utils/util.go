package utils

import (
	"os"

	"sigs.k8s.io/yaml"
)

func LoadFromYaml(path string, cfg interface{}) error {
	b, err := os.ReadFile(path) // #nosec G304 -- path is a trusted CLI --config-file argument
	if err != nil {
		return err
	}
	return yaml.Unmarshal(b, cfg)
}
