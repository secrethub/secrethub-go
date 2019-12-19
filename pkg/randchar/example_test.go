package randchar

import (
	"log"
)

// Generate a 15 character alphanumeric string with at least 3 symbols, 1 uppercase letter,
// 1 lowercase letter and 1 digit.
func ExampleRand_Generate() {
	symbolsRule := Min(3, Symbols)
	uppercaseRule := Min(1, Uppercase)
	lowercaseRule := Min(1, Lowercase)
	numberRule := Min(1, Numeric)

	rand, err := NewRand(All, symbolsRule, uppercaseRule, lowercaseRule, numberRule)
	if err != nil {
		log.Fatal(err)
	}

	val, err := rand.Generate(15)
	if err != nil {
		log.Fatal(err)
	}

	print(string(val))
}

// Generate a 10 character alphanumeric string containing lowercase letters and digits.
func ExampleRand_Generate_customCharset() {
	customCharset := NewCharset("abcdefghijklmnopqrstuvwxyz0123456789")
	rand, err := NewRand(customCharset)
	if err != nil {
		log.Fatal(err)
	}

	val, err := rand.Generate(15)
	if err != nil {
		log.Fatal(err)
	}

	print(string(val))
}
