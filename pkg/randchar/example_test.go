package randchar_test

import (
	"github.com/secrethub/secrethub-go/pkg/randchar"
	"log"
)

// Generate a random slice of 30 alphanumeric characters.
func ExampleRand_Generate() {
	val, err := randchar.Generate(30)
	if err != nil {
		log.Fatal(err)
	}
	print(string(val))
}

// Generate a 15 character alphanumeric string with at least 3 symbols, 1 uppercase letter,
// 1 lowercase letter and 1 digit.
func ExampleRand_Generate_withRules() {
	symbolsRule := randchar.Min(3, randchar.Symbols)
	uppercaseRule := randchar.Min(1, randchar.Uppercase)
	lowercaseRule := randchar.Min(1, randchar.Lowercase)
	numberRule := randchar.Min(1, randchar.Numeric)

	rand, err := randchar.NewRand(randchar.All, symbolsRule, uppercaseRule, lowercaseRule, numberRule)
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
func ExampleRand_Generate_combineCharsets() {
	customCharset := randchar.Lowercase.Add(randchar.Numeric)
	rand, err := randchar.NewRand(customCharset)
	if err != nil {
		log.Fatal(err)
	}

	val, err := rand.Generate(10)
	if err != nil {
		log.Fatal(err)
	}
	print(string(val))
}

// Generate an 8 character long hexadecimal string.
func ExampleRand_Generate_customCharset() {
	hexCharset := randchar.NewCharset("0123456789ABCDEF")
	rand, err := randchar.NewRand(hexCharset)
	if err != nil {
		log.Fatal(err)
	}

	val, err := rand.Generate(8)
	if err != nil {
		log.Fatal(err)
	}
	print(string(val))
}
