package http

import (
	"errors"
	"golang-clean-architecture/internal/model"
	"golang-clean-architecture/internal/shared/exception"
	"golang-clean-architecture/internal/shared/response"
	"golang-clean-architecture/internal/usecase"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type TransferController struct {
	Log             *logrus.Logger
	TransferUseCase *usecase.TransferUseCase
}

func NewTransferController(log *logrus.Logger, transferUseCase *usecase.TransferUseCase) *TransferController {
	return &TransferController{Log: log, TransferUseCase: transferUseCase}
}

func (c *TransferController) Initiate(ctx *fiber.Ctx) error {
	correlationID := ctx.Locals("correlationId").(string)
	userID := ctx.Locals("userId").(uuid.UUID)

	req := new(model.InitiateTransferRequest)
	if err := ctx.BodyParser(req); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(
			response.Error("Invalid request body", correlationID),
		)
	}

	resp, err := c.TransferUseCase.Initiate(ctx.Context(), userID, req)
	if err != nil {
		return c.handleError(ctx, err, correlationID)
	}

	return ctx.Status(fiber.StatusCreated).JSON(
		response.Success("Transfer initiated", resp, correlationID),
	)
}

func (c *TransferController) Confirm(ctx *fiber.Ctx) error {
	correlationID := ctx.Locals("correlationId").(string)
	userID := ctx.Locals("userId").(uuid.UUID)
	referenceID := ctx.Params("referenceId")

	resp, err := c.TransferUseCase.Confirm(ctx.Context(), userID, referenceID)
	if err != nil {
		return c.handleError(ctx, err, correlationID)
	}

	return ctx.Status(fiber.StatusOK).JSON(
		response.Success("Transfer confirmed", resp, correlationID),
	)
}

func (c *TransferController) Cancel(ctx *fiber.Ctx) error {
	correlationID := ctx.Locals("correlationId").(string)
	userID := ctx.Locals("userId").(uuid.UUID)
	referenceID := ctx.Params("referenceId")

	req := new(model.CancelTransferRequest)
	if err := ctx.BodyParser(req); err != nil {
		req = &model.CancelTransferRequest{}
	}

	resp, err := c.TransferUseCase.Cancel(ctx.Context(), userID, referenceID, req)
	if err != nil {
		return c.handleError(ctx, err, correlationID)
	}

	return ctx.Status(fiber.StatusOK).JSON(
		response.Success("Transfer cancelled", resp, correlationID),
	)
}

func (c *TransferController) GetDetail(ctx *fiber.Ctx) error {
	correlationID := ctx.Locals("correlationId").(string)
	userID := ctx.Locals("userId").(uuid.UUID)
	referenceID := ctx.Params("referenceId")

	resp, err := c.TransferUseCase.GetDetail(ctx.Context(), userID, referenceID)
	if err != nil {
		return c.handleError(ctx, err, correlationID)
	}

	return ctx.Status(fiber.StatusOK).JSON(
		response.Success("Transfer detail retrieved", resp, correlationID),
	)
}

func (c *TransferController) GetMyTransfers(ctx *fiber.Ctx) error {
	correlationID := ctx.Locals("correlationId").(string)
	userID := ctx.Locals("userId").(uuid.UUID)

	params := &model.TransferQueryParams{
		Status: ctx.Query("status"),
		From:   ctx.Query("from"),
		To:     ctx.Query("to"),
		Page:   ctx.QueryInt("page", 0),
		Size:   ctx.QueryInt("size", 20),
	}

	resp, err := c.TransferUseCase.GetMyTransfers(ctx.Context(), userID, params)
	if err != nil {
		return c.handleError(ctx, err, correlationID)
	}

	return ctx.Status(fiber.StatusOK).JSON(
		response.SuccessWithPagination("Transfers retrieved", resp.Data, model.Pagination{
			Page:       resp.Pagination.Page,
			Limit:      resp.Pagination.Limit,
			TotalItems: resp.Pagination.TotalItems,
			TotalPages: resp.Pagination.TotalPages,
		}, correlationID),
	)
}

func (c *TransferController) GetAccountHistory(ctx *fiber.Ctx) error {
	correlationID := ctx.Locals("correlationId").(string)
	userID := ctx.Locals("userId").(uuid.UUID)
	accountNumber := ctx.Params("accountNumber")

	params := &model.TransferQueryParams{
		From: ctx.Query("from"),
		To:   ctx.Query("to"),
		Page: ctx.QueryInt("page", 0),
		Size: ctx.QueryInt("size", 20),
	}

	resp, err := c.TransferUseCase.GetAccountHistory(ctx.Context(), userID, accountNumber, params)
	if err != nil {
		return c.handleError(ctx, err, correlationID)
	}

	return ctx.Status(fiber.StatusOK).JSON(
		response.SuccessWithPagination("Account history retrieved", resp.Data, model.Pagination{
			Page:       resp.Pagination.Page,
			Limit:      resp.Pagination.Limit,
			TotalItems: resp.Pagination.TotalItems,
			TotalPages: resp.Pagination.TotalPages,
		}, correlationID),
	)
}

// --------------------------------------------
// PRIVATE HELPER
// --------------------------------------------
func (c *TransferController) handleError(ctx *fiber.Ctx, err error, correlationID string) error {
	switch {
	case errors.Is(err, exception.ErrTransferNotFound):
		return ctx.Status(fiber.StatusNotFound).JSON(
			response.Error(err.Error(), correlationID),
		)
	case errors.Is(err, exception.ErrTransferNotConfirmable),
		errors.Is(err, exception.ErrTransferNotCancellable):
		return ctx.Status(fiber.StatusConflict).JSON(
			response.Error(err.Error(), correlationID),
		)
	case errors.Is(err, exception.ErrTargetAccountNotActive),
		errors.Is(err, exception.ErrInsufficientBalance),
		errors.Is(err, exception.ErrAccountFrozen),
		errors.Is(err, exception.ErrAccountClosed),
		errors.Is(err, exception.ErrAccountNotFound):
		return ctx.Status(fiber.StatusUnprocessableEntity).JSON(
			response.Error(err.Error(), correlationID),
		)
	default:
		c.Log.Errorf("Unhandled error: %v", err)
		return ctx.Status(fiber.StatusInternalServerError).JSON(
			response.Error("Internal server error", correlationID),
		)
	}
}
