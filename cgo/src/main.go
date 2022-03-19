package main

/*
#cgo CFLAGS: -I "../lib/include"
#cgo LDFLAGS: -L "../lib/build2" -lcalc -lstdc++

#include "myheader.hpp"

int SetUp(int a, int b)
{
	return myadd(a, b);
}
*/
import "C"
import "fmt"

func main() {
	a := C.int(3)
	b := C.int(4)

	ret := C.SetUp(a, b)
	fmt.Println("ret", ret)
}
