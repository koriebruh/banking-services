package response

import "time"

type Pagination struct {
	Page       int   `json:"page"`
	Limit      int   `json:"limit"`
	TotalItems int64 `json:"total_items"`
	TotalPages int64 `json:"total_pages"`
}

func SuccessWithPagination[T any](
	message string,
	data T,
	pagination Pagination,
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
