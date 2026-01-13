package limiter

import "github.com/xmplusdev/xray-core/v26/common/errors"

func newError(values ...interface{}) *errors.Error {
	return errors.New(values...)
}
