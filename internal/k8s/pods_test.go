package k8s

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestUpsertLookup(t *testing.T) {
	p := &Pods{byUID: map[string]Pod{}}
	p.upsert(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "db", UID: "u1"},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{
			{Name: "fio", ContainerID: "containerd://abc123"},
		}},
	})
	got, ok := p.Lookup("u1")
	if !ok || got.Name != "db" || got.Containers["abc123"] != "fio" {
		t.Errorf("got %+v %v", got, ok)
	}
	var nilPods *Pods
	if _, ok := nilPods.Lookup("u1"); ok {
		t.Error("nil Pods should find nothing")
	}
}
