package user

import "errors"

var ErrUserNotFound = errors.New("user not found")
var ErrPhoneNumberAlreadyRegistered = errors.New("phone number already registered")
var ErrUsernameAlreadyRegistered = errors.New("username already registered")
var ErrPendingRegistrationNotFound = errors.New("pending registration not found")
var ErrInvalidOTPCode = errors.New("invalid otp code")
var ErrOTPExpired = errors.New("otp has expired")
var ErrUnsupportedTelCode = errors.New("phone tel code is unsupported")
