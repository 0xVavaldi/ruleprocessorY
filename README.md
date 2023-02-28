# ruleprocessorY
![Main Build](https://github.com/TheWorkingDeveloper/ruleprocessorY/actions/workflows/cmake.yml/badge.svg) 
![CodeQL](https://github.com/TheWorkingDeveloper/ruleprocessorY/actions/workflows/codeql-analysis.yml/badge.svg)

Rule Processor Y is a next-gen Rule processor with multibyte character support. It applies rules to wordlists in order to transform them in whichever way the user pleases.
The key feature of this ruleprocessor is that it allows a user to quickly do multibyte or multi-character replacements such as replacing the e with é or the other way around for normalization of wordlists.

## Requirements
```
sudo apt-get install build-essential cmake git
```

## Quickstart
If you receive an error regarding your cmake version, edit CMakeLists.txt and lower the cmake_minimum_required to match your version, this will generally not cause an issue. 
```
git clone https://github.com/TheWorkingDeveloper/ruleprocessorY
cd ruleprocessorY
cmake .
make
./ruleprocessorY -h
./ruleprocessorY -w rockyou.txt -r example_rules.json
```

## Rule writing
Rules are stored using a tab separated format (TSV), which is CSV, but with tabs; Within each line you can utilize the standard rules you might be familiar with in Hashcat (https://hashcat.net/wiki/doku.php?id=rule_based_attack). An example is shown below:
```tsv
c
u   $1  $2  $3
l
$1  $2
$2  $0  $0  $0
^a  ^m
```

Additionally, we support multi-character rules. Allowing the appending, prepending or replacing of multiple characters. To do this we utilize the / delimiter, similar to some unix tools.
A known issue is being unable to use the / character. This is a planned feature where we will make use of $HEX[]
Below is a sample file with comments explaining the construct in an example. 
```tsv
l   $2022
u   $2000
^prefix     $suffix
s/a/4   sa@     # this is two different formats replacing one character with another, both are supported
s/alpha/beta
o0beta
o/0/beta
```

### Hashcat cross-comptability
Finally, using the --hashcat-input flag we support hashcat formatted rules (space/no delimiter). This will automatically attempt to parse the rules and convert them into the TSV format.
In doing so it will replace tabs with \x90 and spaces with \x20. Hashcat supports this notation and the rules will be cross compatible if you were to replace all tabs in the output file with spaces. (or removing tabs entirely).

### Note on duplicate candidates
Candidates matching the original word are never printed unless the `:` rule is specified. This is done to prevent duplicates. Example: Using `l` will only print candidates that have an uppercase character and as a result are different from the original plaintext. This can be unfavorable when working with rejection rules. In that case a `:` must be added as a first rule. An example is shown below where the goal is to reject all candidates containing the word "test". To match case toggled candidates the `l` rule is added before the match test. To ensure all candidates are printed and not just rules with uppercase the `:` rule is added, which will force all candidates to be printed.
```tsv
:
l
!test
```


## Rule Optimizing
Rules generated or used by hashcat can contain contradictions or operations that do not make sense. RuleProcessorY is capable of cleaning up your rules and structuring it out for you. In total we current support 3 forms of optimization. Starting off we can look at some operations that 'do nothing', we refer to this as a no-op (no-operation). Using the --optimize-no-op we remove these. 
```tsv
T0  T0
$1  ]
^1  [
```
