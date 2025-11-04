// Synthetic sketchy JavaScript with ~85% PUA ratio
const config = {
    apiKey: "normal-api-key-12345",
    endpoint: "https://api.example.com"
};

// This string has 85% PUA ratio - should trigger detection
// 17 PUA chars, 3 normal chars = 85%
const encoded = `󠅦󠅑󠅢󠅓󠅢󠅕󠅔󠅕󠅖󠅀󠅢󠅓󠅤󠅔󠅕󠅖󠅀󠅢abc`;

function decode(str) {
    return str.replace(/[^\w]/g, '');
}

const data = decode(encoded);
