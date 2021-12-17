# ruleprocessorY
Rule Processor Y is a next-gen Rule processor with multibyte character support. It applies rules to wordlists in order to transform them in whichever way the user pleases.
The key feature of this ruleprocessor is that it allows a user to quickly do multibyte or multi-character replacements such as replacing the e with é or the other way around for normalization of wordlists.

## Installation Requirements
```
apt install <to be written>
```

## Quickstart
```
git clone https://github.com/TheWorkingDeveloper/ruleprocessorY
cd ruleprocessorY
cmake .
make
./ruleprocessorY -h
./ruleprocessorY -w rockyou.txt -r example_rules.json
```

## Rule writing
Rules are always stored inside a json array; this will be referred to as the 'root array'. Within this array, strings can be placed with the standard rules you might be familiar with in Hashcat (https://hashcat.net/wiki/doku.php?id=rule_based_attack). **This does not allow for multiple rules to be executed on the same plain**. An example is shown below:

```json
[
    "c",
    "u",
    "l",
    "$1",
    "$2",
    "^a"
]
```

The alternative and primary method rules will be defined it is by putting them in individual arrays. The main construction of the list is as follows:
- 1 'root array' to contain all rules.
- 1 array or string containing a series of rules or a single rule respectively
- 1 or multiple arrays - each containing a rule to be used on a plaintext candidate
- 1, 2, 3 strings depending on the rule containing the type and values used for the rule.

Below is a sample file with comments explaining the construct in an example.
```
[ # Main Root array
    "c",  # Example of a string rule using the old style - capitalizing the candidate
    "u",  # Another example of the old style converting the candidate to uppercase
    [  # List containing one rule to be used on each candidate
        ["s", "A", "C"]  # Replace all "A" characters with "C"
    ],
    "sAC"  # Perform the EXACT same operation as above in the old format, a short version of writing it.
    [
        ["s", "1", "2"],  # Replace all 1 characters with 2
        ["u"]  # Convert all characters to uppercase (after converting 1 to 2)
    ],  # The old format would be writing "s12 u"
    [  # the next example shows more of the possibilities that are new with this tool
        ["$","123456abcdef"],  # Append a whole series of characters
        ["é","e"], # a series of rules to normalize "e" characters after having appended 123456abcdef to the rule.
        ["è","e"],
        ["ê","e"]
    ]
]
```
