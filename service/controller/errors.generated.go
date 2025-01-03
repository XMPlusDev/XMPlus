package controller

import "github.com/xmplusdev/xray-core/v25/common/errors"

func newError(values ...interface{}) *errors.Error {
	return errors.New(values...)
}
