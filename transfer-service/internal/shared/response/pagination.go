package response

import (
	"golang-clean-architecture/internal/model"
	"time"
)

func SuccessWithPagination[T any](
	message string,
	data T,
	pagination model.Pagination,
	correlationID string,
) ApiResponse[T] {
	return ApiResponse[T]{
		Success:    true,
		Message:    message,
		Data:       &data,
		Pagination: &pagination,
		Meta: Meta{
			Timestamp:     time.Now(),
			CorrelationID: correlationID,
			Service:       ServiceName,
			Version:       Version,
		},
	}
}
