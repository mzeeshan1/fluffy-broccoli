package main

import "fmt"

func main() {
	colors := make(map[string]string)
	colors["red"] = "0xffff"
	colors["green"] = "0x0000"
	// fmt.Println(colors)
	// delete(colors, "hello")
	// fmt.Println(colors)
	printMap(colors)
}

func printMap(c map[string]string) {
	for color, hex := range c {
		fmt.Println("Hex code for color", color, " is", hex)
	}
}
