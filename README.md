# ruleprocessorY
![Main Build](https://github.com/TheWorkingDeveloper/ruleprocessorY/actions/workflows/cmake.yml/badge.svg) 
![CodeQL](https://github.com/TheWorkingDeveloper/ruleprocessorY/actions/workflows/codeql-analysis.yml/badge.svg)

Rule Processor Y is a next-gen Rule processor with multibyte character support built for hashcat. It applies rules to wordlists in order to transform them in whichever way the user pleases.
The key feature of this ruleprocessor is that it allows a user to quickly do multibyte or multi-character replacements such as replacing the e with é or the other way around for normalization of wordlists.

## Requirements
```
sudo apt-get install build-essential cmake git
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

The alternative and primary method rules will be defined in, is by putting them in individual arrays. The main construction of the list is as follows:
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
        ["s","é","e"], # a series of rules to normalize "e" characters after having appended 123456abcdef to the rule.
        ["s","è","e"],
        ["s","ê","e"]
    ],
    [
        [":"], # Rejection rules on : require ":" to ALWAYS be first.
        ["<", "6"] # Reject plains less than 6 characters
    ],
    [
        ["q"], # duplicate every character. Test => TTeesstt
        ["<", "6"] # Reject plains less than 6 characters after executing previous rule
    ]
]
```

### Note on duplicate candidates
Candidates matching the original word are never printed unless the `:` rule is specified. This is done to prevent duplicates. Example: Using `l` will only print candidates that have an uppercase character and as a result are different from the original plaintext. This can be unfavorable when working with rejection rules. In that case a `:` must be added as a first rule. An example is shown below where the goal is to reject all candidates containing the word "test". To match case toggled candidates the `l` rule is added before the match test. To ensure all candidates are printed and not just rules with uppercase the `:` rule is added, which will force all candidates to be printed.
```json
[
    [
        [":"],
        ["l"],
        ["!", "test"]
    ]
]
```
