package response

import (
	"golang-clean-architecture/internal/model"
	"time"
)

var (
	ServiceName = "transfer-service"
	Version     = "1.0.0"
)

type ApiResponse[T any] struct {
	Success    bool              `json:"success"`
	Message    string            `json:"message,omitempty"`
	Data       *T                `json:"data,omitempty"`
	Errors     map[string]string `json:"errors,omitempty"`
	Pagination *model.Pagination `json:"pagination,omitempty"`
	Meta       Meta              `json:"meta"`
}

type Meta struct {
	Timestamp     time.Time `json:"timestamp"`
	CorrelationID string    `json:"correlation_id"`
	Service       string    `json:"service"`
	Version       string    `json:"version"`
}
