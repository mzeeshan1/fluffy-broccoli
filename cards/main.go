package main

func main() {
	// var card string = "Ace of Spades"
	// cards := newDeck()
	// cards.writeToFile("my_cards")
	cards := readDeckFromFile("my_cards")
	cards.print()
	cards.Shuffle()
	cards.print()
	// cards.print()
	// cards, remainingCards := deal(cards, 5)
	// remainingCards.print()
}
func cardVal() string {
	return "Ace of Spades"
}
