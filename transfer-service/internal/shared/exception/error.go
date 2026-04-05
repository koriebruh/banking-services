package exception

import "errors"

var (
	ErrTransferNotFound       = errors.New("TRANSFER_NOT_FOUND")
	ErrTransferNotConfirmable = errors.New("TRANSFER_NOT_CONFIRMABLE")
	ErrTransferNotCancellable = errors.New("TRANSFER_NOT_CANCELLABLE")
)

// Account errors (dari gRPC response)
var (
	ErrAccountNotFound        = errors.New("ACCOUNT_NOT_FOUND")
	ErrAccountNotActive       = errors.New("ACCOUNT_NOT_ACTIVE")
	ErrTargetAccountNotActive = errors.New("TARGET_ACCOUNT_NOT_ACTIVE")
	ErrInsufficientBalance    = errors.New("INSUFFICIENT_BALANCE")
	ErrAccountFrozen          = errors.New("ACCOUNT_FROZEN")
	ErrAccountClosed          = errors.New("ACCOUNT_CLOSED")
)
