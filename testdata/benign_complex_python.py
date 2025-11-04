#!/usr/bin/env python3
"""Complex benign Python with edge cases"""

# Various string types
simple = "simple string"
single = 'single quoted'
triple_double = """Multi-line
string with
line breaks"""
triple_single = '''Another
multi-line
string'''

# Escaped characters
escaped = "String with \"quotes\" and \\backslashes\\"
raw_string = r"Raw string \n not escaped"
formatted = f"Formatted {simple} with variables"

# Unicode but NOT PUA
unicode_str = "Hello 世界 мир 🌍"
emoji = "😀🎉🚀"

# Bytes (not strings but might appear)
byte_string = b"byte string"

# Dictionary with strings
config = {
    "key1": "value1",
    "key2": 'value2',
    "nested": {
        "deep": "nested value"
    }
}

# List of strings
items = [
    "first",
    "second",
    'third with "quotes"',
    f"formatted {simple}"
]

# Function with string return
def get_message():
    return "function string"

# String concatenation
concat = "part1" + "part2" + 'part3'

# Multi-line with parentheses
long_string = ("This is a very long string "
               "that spans multiple lines "
               "using implicit concatenation")

# Comments with "strings" should be ignored
# "this is a comment"
# 'another comment'

class Example:
    """Class docstring with 'quotes' and "double quotes" """

    def method(self):
        """Method docstring"""
        return "method return value"
