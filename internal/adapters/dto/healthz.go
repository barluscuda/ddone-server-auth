package dto

import "time"

type ResHealthz struct {
	Message    string    `json:"message"`
	Active     bool      `json:"active"`
	ServerTime time.Time `json:"serverTime"`
}
