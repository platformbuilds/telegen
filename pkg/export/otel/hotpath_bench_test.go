package otel

import (
	"context"
	"testing"
	"time"

	expirable2 "github.com/hashicorp/golang-lru/v2/expirable"
	"go.opentelemetry.io/otel/attribute"

	"github.com/mirastacklabs-ai/telegen/internal/appolly/app/request"
	"github.com/mirastacklabs-ai/telegen/internal/appolly/app/svc"
	"github.com/mirastacklabs-ai/telegen/pkg/export/attributes"
	"github.com/mirastacklabs-ai/telegen/pkg/export/instrumentations"
	"github.com/mirastacklabs-ai/telegen/pkg/export/otel/metric/api/metric"
	"github.com/mirastacklabs-ai/telegen/pkg/export/otel/tracesgen"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

type benchMetric struct{}

func (benchMetric) Remove(context.Context, ...metric.RemoveOption) {}

var benchmarkAttrsCache = expirable2.NewLRU[svc.UID, []attribute.KeyValue](256, nil, time.Hour)

func BenchmarkMetricRecord(b *testing.B) {
	ex := NewExpirer[*request.Span, benchMetric, float64](
		context.Background(),
		benchMetric{},
		[]attributes.Field[*request.Span, attribute.KeyValue]{
			{
				ExposedName: "http.method",
				Get: func(s *request.Span) attribute.KeyValue {
					return attribute.String("http.method", s.Method)
				},
			},
			{
				ExposedName: "service.name",
				Get: func(s *request.Span) attribute.KeyValue {
					return attribute.String("service.name", s.Service.UID.Name)
				},
			},
		},
		time.Now,
		time.Hour,
	)
	span := &request.Span{
		Method: "GET",
		Service: svc.Attrs{
			UID: svc.UID{Name: "checkout", Namespace: "payments"},
		},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ex.ForRecord(span)
	}
}

func BenchmarkTracesGen(b *testing.B) {
	spans := make([]request.Span, 128)
	for i := range spans {
		spans[i] = request.Span{
			Type:         request.EventTypeHTTP,
			Method:       "GET",
			Path:         "/checkout",
			Status:       200,
			RequestStart: 1,
			Start:        2,
			End:          3,
			Service: svc.Attrs{
				UID: svc.UID{Name: "checkout", Namespace: "payments", Instance: "pod-a"},
			},
		}
	}
	selection := instrumentations.NewInstrumentationSelection(
		[]instrumentations.Instrumentation{instrumentations.InstrumentationALL},
	)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		grouped := tracesgen.GroupSpans(context.Background(), spans, nil, sdktrace.AlwaysSample(), selection)
		for _, group := range grouped {
			if len(group) == 0 {
				continue
			}
			_ = tracesgen.GenerateTracesWithAttributes(
				benchmarkAttrsCache,
				&group[0].Span.Service,
				nil,
				"host-a",
				group,
				"benchmark",
			)
		}
	}
}
