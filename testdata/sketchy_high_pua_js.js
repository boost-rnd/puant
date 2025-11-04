// Synthetic sketchy JavaScript with 90% PUA characters
const normalCode = "this is benign";

// This string has a very high PUA ratio (90%+) - similar to real malware
const payload = `󠅦󠅑󠅢󠄐󠅏󠅏󠅓󠅢󠅕󠅑󠅤󠅕󠄭󠄿󠅒󠅚󠅕󠅓󠅤󠄞󠅓󠅢󠅕󠅑󠅤󠅕󠄫󠅦󠅑󠅢󠄐󠅏󠅏󠅔󠅕󠅖󠅀󠅢󠅟󠅠󠄭󠄿󠅒󠅚󠅕󠅓󠅤󠄞󠅔󠅕󠅖󠅙󠅞󠅕󠅀󠅢󠅟󠅠󠅕󠅢󠅤󠅩󠄫󠅦󠅑󠅢󠄐󠅏󠅏󠅗󠅕󠅤󠄿󠅧󠅞󠅀󠅢󠅟󠅠󠄴󠅕󠅣󠅓󠄭󠄿󠅒󠅚󠅕󠅓󠅤󠄞󠅗󠅕󠅤󠄿󠅧󠅞󠅀󠅢󠅟󠅠󠅕󠅢󠅤󠅩󠄴󠅕󠅣󠅓󠅢󠅙󠅠󠅤󠅟󠅢`;

function obfuscatedFunction() {
    eval(payload);
}

console.log(normalCode);
