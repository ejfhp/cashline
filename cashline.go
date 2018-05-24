package main

import (
	"fmt"
)

func main() {
	x, y := 3, 34
	boh := x<<8 + y<<16
	fmt.Println(boh)
}
