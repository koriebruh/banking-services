package response

import "time"

func Success[T any](message string, data T, correlationID string) ApiResponse[T] {
	return ApiResponse[T]{
		Success: true,
		Message: message,
		Data:    &data,
		Meta: Meta{
			Timestamp:     time.Now(),
			CorrelationID: correlationID,
			Service:       ServiceName,
			Version:       Version,
		},
	}
}
