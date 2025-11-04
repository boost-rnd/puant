// Complex benign JavaScript with edge cases
const complexStrings = {
    // Escaped quotes
    escaped: "He said, \"Hello!\"",
    singleEscaped: 'It\'s a test',

    // Multi-line template literals
    template: `This is a
    multi-line
    template string with ${variable}`,

    // Unicode but NOT PUA
    unicode: "Hello 世界 мир 🌍",

    // Strings in object literals
    nested: {
        deep: {
            value: "nested string"
        }
    },

    // Array of strings
    list: [
        "first",
        "second",
        "third with \"quotes\"",
        `template ${x}`
    ],

    // Function with string returns
    getMessage: function() {
        return "function string";
    },

    // String concatenation
    concat: "part1" + "part2" + 'part3',

    // Regex strings (should not be detected)
    pattern: /test[a-z]+/g,

    // Comments with "quotes" should be ignored
    // "this is a comment"
    /* "multiline
       comment string" */
};

// Function calls with strings
console.log("Regular console output");
console.error('Error message');
fetch(`https://api.example.com/${endpoint}`);
