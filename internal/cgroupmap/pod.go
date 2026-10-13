package cgroupmap

import (
	"regexp"
	"strings"
)

// PodRef is what we can learn about a cgroup from its path alone.
// pod name and namespace need the k8s api, see internal/k8s
type PodRef struct {
	PodUID      string
	ContainerID string
	QoS         string // guaranteed, burstable, besteffort
}

var (
	// systemd driver: kubepods-burstable-pod1234_5678.slice, dashes in the
	// uid became underscores. also matches kinds kubelet-kubepods-... prefix
	systemdPod = regexp.MustCompile(`^(?:[a-z]+-)*kubepods(?:-(burstable|besteffort))?-pod([0-9a-f_]+)\.slice$`)
	// cgroupfs driver: pod1234-5678
	cgroupfsPod = regexp.MustCompile(`^pod([0-9a-f-]+)$`)
	// cri-containerd-<id>.scope, crio-<id>.scope, docker-<id>.scope
	systemdCtr = regexp.MustCompile(`^(?:cri-containerd|crio|docker)-([0-9a-f]{64})\.scope$`)
	bareCtr    = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ParsePath pulls pod uid and container id out of a kubelet cgroup path.
// handles both cgroup drivers and the nesting kind adds in front. ok is
// false for anything that isnt under kubepods
func ParsePath(path string) (PodRef, bool) {
	var ref PodRef
	parts := strings.Split(strings.Trim(path, "/"), "/")
	inKube := false
	for i, p := range parts {
		switch {
		case p == "kubepods" || strings.HasSuffix(p, "kubepods.slice"):
			inKube = true
		case inKube && (p == "burstable" || p == "besteffort"):
			ref.QoS = p
		case systemdPod.MatchString(p):
			m := systemdPod.FindStringSubmatch(p)
			inKube = true
			ref.QoS = qos(m[1])
			ref.PodUID = strings.ReplaceAll(m[2], "_", "-")
		case inKube && cgroupfsPod.MatchString(p):
			ref.PodUID = cgroupfsPod.FindStringSubmatch(p)[1]
			if ref.QoS == "" {
				ref.QoS = "guaranteed"
			}
		case ref.PodUID != "" && i == len(parts)-1:
			if m := systemdCtr.FindStringSubmatch(p); m != nil {
				ref.ContainerID = m[1]
			} else if bareCtr.MatchString(p) {
				ref.ContainerID = p
			}
		}
	}
	return ref, ref.PodUID != ""
}

func qos(s string) string {
	if s == "" {
		return "guaranteed"
	}
	return s
}
