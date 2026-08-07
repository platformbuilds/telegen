package transform

import (
	"testing"

	"github.com/mirastacklabs-ai/telegen/internal/appolly/app/svc"
	"github.com/mirastacklabs-ai/telegen/internal/kube"
	"github.com/mirastacklabs-ai/telegen/internal/kube/kubecache/informer"
	"github.com/mirastacklabs-ai/telegen/internal/kube/kubecache/meta"
	ikube "github.com/mirastacklabs-ai/telegen/internal/kubei"
	"github.com/mirastacklabs-ai/telegen/pkg/export/imetrics"
)

type benchNotifier struct{}

func (benchNotifier) Subscribe(meta.Observer)   {}
func (benchNotifier) Unsubscribe(meta.Observer) {}
func (benchNotifier) Notify(*informer.Event)    {}

func BenchmarkKubeDecorate(b *testing.B) {
	store := kube.NewStore(benchNotifier{}, kube.ResourceLabels{}, nil, imetrics.NoopReporter{})
	metaObj := &ikube.CachedObjMeta{
		Meta: &informer.ObjectMeta{
			Name:      "checkout-pod",
			Namespace: "payments",
			Pod: &informer.PodInfo{
				Uid:          "pod-uid",
				NodeName:     "node-a",
				StartTimeStr: "2026-01-15T10:30:45Z",
				Owners: []*informer.Owner{
					{Name: "checkout-deploy", Kind: "Deployment"},
				},
			},
		},
	}

	// Warm metadata cache once before timing.
	warm := svc.Attrs{}
	AppendKubeMetadata(store, &warm, metaObj, "prod-cluster", "checkout")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		attrs := svc.Attrs{}
		AppendKubeMetadata(store, &attrs, metaObj, "prod-cluster", "checkout")
	}
}
