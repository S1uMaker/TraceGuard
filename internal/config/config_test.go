package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validConfig = `{"bpf_object":"build/exec.bpf.o","docker_socket":"/var/run/docker.sock","cgroup_root":"/sys/fs/cgroup","proc_root":"/proc","output_dir":"data","refresh_seconds":5,"include_host":false,"rules":[{"id":"shell","name":"Shell","severity":"warning","scope":"docker","executables":["sh"],"uid":0,"enabled":true}]}`

func loadFixture(t *testing.T, data string) (Config, error) {
	t.Helper()
	filename := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(filename, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	return Load(filename)
}

func TestLoadPreservesExplicitRootUID(t *testing.T) {
	cfg, err := loadFixture(t, validConfig)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Rules) != 1 || cfg.Rules[0].UID == nil || *cfg.Rules[0].UID != 0 || !cfg.Rules[0].Enabled {
		t.Fatalf("explicit UID zero or rule enablement lost: %#v", cfg.Rules)
	}
}

func TestLoadRejectsInvalidConfigurations(t *testing.T) {
	cases := map[string]string{
		"unknown field":            strings.Replace(validConfig, `"include_host":false`, `"incldue_host":false`, 1),
		"duplicate field":          strings.Replace(validConfig, `"include_host":false`, `"include_host":false,"include_host":true`, 1),
		"case alias":               strings.Replace(validConfig, `"include_host":false`, `"include_host":false,"Include_Host":true`, 1),
		"trailing JSON":            validConfig + `{}`,
		"relative socket":          strings.Replace(validConfig, `/var/run/docker.sock`, `docker.sock`, 1),
		"zero refresh":             strings.Replace(validConfig, `"refresh_seconds":5`, `"refresh_seconds":0`, 1),
		"misspelled scope":         strings.Replace(validConfig, `"scope":"docker"`, `"scope":"dockre"`, 1),
		"empty executable list":    strings.Replace(validConfig, `"executables":["sh"]`, `"executables":[]`, 1),
		"relative executable path": strings.Replace(validConfig, `"executables":["sh"]`, `"executables":["bin/sh"]`, 1),
		"negative UID":             strings.Replace(validConfig, `"uid":0`, `"uid":-1`, 1),
		"overflow UID":             strings.Replace(validConfig, `"uid":0`, `"uid":4294967296`, 1),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := loadFixture(t, data); err == nil {
				t.Fatal("invalid configuration was accepted")
			}
		})
	}
}
