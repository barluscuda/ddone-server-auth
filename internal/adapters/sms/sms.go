package sms

import "github.com/barluscuda/dextools/wenova"

type SMS struct {
	wnv *wenova.Wenova
}

func NewSMS(wnv *wenova.Wenova) SMS {
	return SMS{
		wnv: wnv,
	}
}