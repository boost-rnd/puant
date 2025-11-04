// Synthetic test case right at the 80% threshold
const benignString = "This is a normal string";

// This string has exactly 80% PUA characters - edge case for threshold testing
// 16 PUA chars out of 20 total = 80%
const thresholdTest = `󠅦󠅑󠅢󠅓󠅢󠅕󠅔󠅕󠅖󠅀󠅢󠅓󠅤󠅔󠅕󠅖abcd`;

console.log(benignString);
