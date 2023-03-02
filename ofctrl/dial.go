//go:build linux || darwin
// +build linux darwin

package ofctrl

import "net"

func DialUnixOrNamedPipe(address string) (net.Conn, error) {
	return net.Dial("unix", address)
}
