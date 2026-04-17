package telemetry

import (
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/trace"
)

type Providers struct {
	TracerProvider *trace.TracerProvider
	MeterProvider  *metric.MeterProvider
}
