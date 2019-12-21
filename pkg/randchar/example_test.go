package randchar

import (
	"log"
)

// Generate a random slice of 30 alphanumeric characters.
func ExampleRand_Generate() {
	val, err := Generate(30)
	if err != nil {
		log.Fatal(err)
	}
	print(string(val))
}

// Generate a 15 character alphanumeric string with at least 3 symbols, 1 uppercase letter,
// 1 lowercase letter and 1 digit.
func ExampleRand_Generate_withRules() {
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
func ExampleRand_Generate_combineCharsets() {
	customCharset := Lowercase.Add(Numeric)
	rand, err := NewRand(customCharset)
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
	hexCharset := NewCharset("0123456789ABCDEF")
	rand, err := NewRand(hexCharset)
	if err != nil {
		log.Fatal(err)
	}

	val, err := rand.Generate(8)
	if err != nil {
		log.Fatal(err)
	}
	print(string(val))
}
