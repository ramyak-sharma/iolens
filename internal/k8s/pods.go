// package k8s keeps an in memory view of the pods on this node so cgroup
// paths (which only carry the pod uid) can be shown as namespace/name.
package k8s

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

type Pod struct {
	Namespace, Name string
	// container id (no runtime:// prefix) -> container name
	Containers map[string]string
}

// Pods is a uid indexed cache fed by an informer limited to one node
type Pods struct {
	mu    sync.RWMutex
	byUID map[string]Pod
	ready bool
}

// Start runs an informer that only watches pods with spec.nodeName=node, so
// each agent only holds its own nodes pods. returns once the first list
// is synced or ctx is done
func Start(ctx context.Context, node string) (*Pods, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("in cluster config: %w", err)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	f := informers.NewSharedInformerFactoryWithOptions(cs, 10*time.Minute,
		informers.WithTweakListOptions(func(o *metav1.ListOptions) {
			o.FieldSelector = fields.OneTermEqualSelector("spec.nodeName", node).String()
		}))
	p := &Pods{byUID: map[string]Pod{}}
	inf := f.Core().V1().Pods().Informer()
	_, err = inf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(o any) { p.upsert(o) },
		UpdateFunc: func(_, o any) { p.upsert(o) },
		DeleteFunc: func(o any) { p.remove(o) },
	})
	if err != nil {
		return nil, err
	}
	f.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), inf.HasSynced) {
		return nil, fmt.Errorf("pod informer never synced")
	}
	p.mu.Lock()
	p.ready = true
	p.mu.Unlock()
	return p, nil
}

// Lookup by pod uid. safe to call on a nil *Pods (k8s disabled)
func (p *Pods) Lookup(uid string) (Pod, bool) {
	if p == nil {
		return Pod{}, false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	pod, ok := p.byUID[uid]
	return pod, ok
}

func (p *Pods) upsert(o any) {
	pod, ok := o.(*corev1.Pod)
	if !ok {
		return
	}
	v := Pod{Namespace: pod.Namespace, Name: pod.Name, Containers: map[string]string{}}
	for _, lists := range [][]corev1.ContainerStatus{
		pod.Status.InitContainerStatuses, pod.Status.ContainerStatuses, pod.Status.EphemeralContainerStatuses,
	} {
		for _, cs := range lists {
			if id := stripRuntime(cs.ContainerID); id != "" {
				v.Containers[id] = cs.Name
			}
		}
	}
	p.mu.Lock()
	p.byUID[string(pod.UID)] = v
	p.mu.Unlock()
}

func (p *Pods) remove(o any) {
	if t, ok := o.(cache.DeletedFinalStateUnknown); ok {
		o = t.Obj
	}
	pod, ok := o.(*corev1.Pod)
	if !ok {
		return
	}
	// keep it a little while, the cgroup can outlive the pod object by a
	// few seconds and wed lose the name for its last samples
	uid := string(pod.UID)
	time.AfterFunc(time.Minute, func() {
		p.mu.Lock()
		delete(p.byUID, uid)
		p.mu.Unlock()
	})
}

// containerd://abc -> abc
func stripRuntime(id string) string {
	if _, after, ok := strings.Cut(id, "://"); ok {
		return after
	}
	return id
}
