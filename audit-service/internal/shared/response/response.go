package response

type WebResponse struct {
	Header Header `json:"header"`
	Data   any    `json:"data,omitempty"`
}

type Header struct {
	IsSuccess     bool     `json:"isSuccess"`
	Errors        []string `json:"errors,omitempty"`
	CorrelationId string   `json:"correlationId,omitempty"`
}

func Error(message string, correlationId string) WebResponse {
	return WebResponse{
		Header: Header{
			IsSuccess:     false,
			Errors:        []string{message},
			CorrelationId: correlationId,
		},
	}
}

func Success(data any, correlationId string) WebResponse {
	return WebResponse{
		Header: Header{
			IsSuccess:     true,
			CorrelationId: correlationId,
		},
		Data: data,
	}
}
