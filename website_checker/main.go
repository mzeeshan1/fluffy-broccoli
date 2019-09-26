package main

import (
	"fmt"
	"net/http"
	"time"
)

func main() {
	links := []string{"https://google.com", "https://google.com", "https://stackoverflow.com", "https://golang.org", "https://amazon.com"}
	c := make(chan string)
	// fmt.Println(link)
	// checkLink()
	for _, l := range links {
		go checkLink(l, c)
	}
	for l := range c {
		func(link string) {
			time.Sleep(5 * time.Second)
			go checkLink(link, c)
		}(l)
	}
}

func checkLink(link string, c chan string) {
	_, err := http.Get(link)
	if err != nil {
		fmt.Println(link, "is down")
		c <- link
		return
	}
	fmt.Println(link, "is up")
	c <- link
}
