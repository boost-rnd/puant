// This is a benign JavaScript file for testing.
// It contains a small number of PUA characters, but not enough to be flagged.

function greet(name) {
  console.log(`Hello, ${name}!`);
}

greet("World");

// A string with just a couple PUA chars (<50%)
// 2 PUA chars out of 10 total = 20% (well below threshold)
const icons = "abc󠅦de󠅑fgh";
console.log(icons);
