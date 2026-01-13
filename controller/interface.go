// To implement controller, one needs to implement the interface below.
package controller

type ControllerInterface interface {
	Start() error
	Close() error
	Restart
}

type Restart interface {
	Start() error
	Close() error
}
