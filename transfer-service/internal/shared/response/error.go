package response

import "time"

func Error(message string, correlationID string) ApiResponse[any] {
	return ApiResponse[any]{
		Success: false,
		Message: message,
		Meta: Meta{
			Timestamp:     time.Now(),
			CorrelationID: correlationID,
			Service:       ServiceName,
			Version:       Version,
		},
	}
}

func Errors(message string, fieldErrors map[string]string, correlationID string) ApiResponse[any] {
	return ApiResponse[any]{
		Success: false,
		Message: message,
		Errors:  fieldErrors,
		Meta: Meta{
			Timestamp:     time.Now(),
			CorrelationID: correlationID,
			Service:       ServiceName,
			Version:       Version,
		},
	}
}
