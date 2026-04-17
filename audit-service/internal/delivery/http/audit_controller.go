package http

import (
	"time"

	"golang-clean-architecture/internal/model"
	"golang-clean-architecture/internal/shared/response"
	"golang-clean-architecture/internal/usecase"

	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

// AuditController menangani HTTP request terkait audit logs.
// Hanya menyediakan satu endpoint read-only (append-only service).
//
// Clean Architecture flow: Controller → Usecase → Repository
type AuditController struct {
	Log     *logrus.Logger
	Usecase *usecase.AuditUsecase
}

// NewAuditController membuat instance AuditController baru.
func NewAuditController(log *logrus.Logger, uc *usecase.AuditUsecase) *AuditController {
	return &AuditController{
		Log:     log,
		Usecase: uc,
	}
}

// FindAll menangani GET /api/audit-logs.
//
// Query Parameters:
//
//	user_code     - Filter berdasarkan user code
//	event_type    - Filter berdasarkan event type (e.g. user.login.success)
//	event_source  - Filter berdasarkan source: AUTH, ACCOUNT, TRANSFER
//	resource_type - Filter berdasarkan resource type: USER, ACCOUNT, TRANSFER
//	resource_id   - Filter berdasarkan resource ID (e.g. account number)
//	start_date    - Filter occurred_at >= date (format: 2006-01-02)
//	end_date      - Filter occurred_at <= date (format: 2006-01-02)
//	page          - Nomor halaman (default: 1)
//	size          - Jumlah per halaman (default: 20, max: 100)
func (c *AuditController) FindAll(ctx *fiber.Ctx) error {
	correlationID, _ := ctx.Locals("correlationId").(string)

	filter := model.AuditLogFilter{
		UserCode:     ctx.Query("user_code"),
		EventType:    ctx.Query("event_type"),
		EventSource:  ctx.Query("event_source"),
		ResourceType: ctx.Query("resource_type"),
		ResourceID:   ctx.Query("resource_id"),
		Page:         ctx.QueryInt("page", 1),
		Size:         ctx.QueryInt("size", 20),
	}

	// Parse date filters
	if startDateStr := ctx.Query("start_date"); startDateStr != "" {
		t, err := time.Parse("2006-01-02", startDateStr)
		if err != nil {
			c.Log.WithField("start_date", startDateStr).Warn("Invalid start_date format")
			return ctx.Status(fiber.StatusBadRequest).JSON(
				response.Error("Invalid start_date format. Expected: YYYY-MM-DD", correlationID),
			)
		}
		filter.StartDate = t
	}

	if endDateStr := ctx.Query("end_date"); endDateStr != "" {
		t, err := time.Parse("2006-01-02", endDateStr)
		if err != nil {
			c.Log.WithField("end_date", endDateStr).Warn("Invalid end_date format")
			return ctx.Status(fiber.StatusBadRequest).JSON(
				response.Error("Invalid end_date format. Expected: YYYY-MM-DD", correlationID),
			)
		}
		// Set ke akhir hari agar inclusive
		filter.EndDate = t.Add(24*time.Hour - time.Nanosecond)
	}

	// Validate event_source if provided
	if filter.EventSource != "" {
		validSources := map[string]bool{"AUTH": true, "ACCOUNT": true, "TRANSFER": true}
		if !validSources[filter.EventSource] {
			return ctx.Status(fiber.StatusBadRequest).JSON(
				response.Error("Invalid event_source. Must be one of: AUTH, ACCOUNT, TRANSFER", correlationID),
			)
		}
	}

	c.Log.WithFields(logrus.Fields{
		"correlation_id": correlationID,
		"user_code":      filter.UserCode,
		"event_source":   filter.EventSource,
		"event_type":     filter.EventType,
		"page":           filter.Page,
		"size":           filter.Size,
	}).Debug("Querying audit logs")

	result, err := c.Usecase.FindAll(ctx.Context(), filter)
	if err != nil {
		c.Log.WithError(err).Error("Failed to query audit logs")
		return ctx.Status(fiber.StatusInternalServerError).JSON(
			response.Error("Failed to retrieve audit logs", correlationID),
		)
	}

	return ctx.Status(fiber.StatusOK).JSON(
		response.Success(result, correlationID),
	)
}
