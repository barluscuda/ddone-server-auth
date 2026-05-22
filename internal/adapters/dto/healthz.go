package dto

import "time"

type ResHealthz struct {
	Success    bool      `json:"success"`
	Code       string    `json:"code"`
	Message    string    `json:"message"`
	Active     bool      `json:"active"`
	ServerTime time.Time `json:"serverTime"`
}
