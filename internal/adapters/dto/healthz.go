package dto

import "time"

type ResHealthz struct {
	Active     bool      `json:"active"`
	ServerTime time.Time `json:"serverTime"`
}
