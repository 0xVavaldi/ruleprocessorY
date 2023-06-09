# ruleprocessorY
![Main Build](https://github.com/0xVavaldi/ruleprocessorY/actions/workflows/cmake.yml/badge.svg) 
![CodeQL](https://github.com/0xVavaldi/ruleprocessorY/actions/workflows/codeql-analysis.yml/badge.svg)

Rule Processor Y is a next-gen Rule processor with multibyte character support built for hashcat. It applies rules to wordlists in order to transform them in whichever way the user pleases.
The key feature of this ruleprocessor is that it allows a user to quickly do multibyte or multi-character replacements such as replacing the e with é or the other way around for normalization of wordlists.

## Requirements
```
sudo apt-get install build-essential cmake git
```

## Quickstart
If you receive an error regarding your cmake version, edit CMakeLists.txt and lower the cmake_minimum_required to match your version, this will generally not cause an issue. 
```
git clone https://github.com/0xVavaldi/ruleprocessorY
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
Finally, using the `--hashcat-input` and/or `--hashcat-output` flag we support hashcat formatted rules (space/no delimiter). This will automatically attempt to parse the rules and convert them into the TSV format.
In doing so it will replace tabs with \x90 and spaces with \x20. Hashcat supports this notation and the rules will be cross compatible if you were to replace all tabs in the output file with spaces. (or removing tabs entirely).

### Note on duplicate candidates
Candidates matching the original word are never printed unless the `:` rule is specified. This is done to prevent duplicates. Example: Using `l` will only print candidates that have an uppercase character and as a result are different from the original plaintext. This can be unfavorable when working with rejection rules. In that case a `:` must be added as a first rule. An example is shown below where the goal is to reject all candidates containing the word "test". To match case toggled candidates the `l` rule is added before the match test. To ensure all candidates are printed and not just rules with uppercase the `:` rule is added, which will force all candidates to be printed.
```bash
ruleprocessorY.exe -r rule.txt --optimize-no-op --hashcat-input --hashcat-output > optimized_rule.txt
```
```tsv
:
l
!test
$1 $2 $3
```


## Rule Optimizing
Rules generated or used by hashcat can contain contradictions or operations that do not make sense. RuleProcessorY is capable of cleaning up your rules and structuring it out for you. In total we current support 3 forms of optimization. Starting off we can look at some operations that 'do nothing', we refer to this as a no-op (no-operation). Using the `--optimize-no-op` we remove these. 
```tsv
T0      T0
$1      ]
^1      [
```

Rules generated or used by hashcat can contain partial contradictions or can be rewritten to be more efficient. This can happen in different ways, but for computational sake we won't entirely rewrite rules. Instead, we will look if the rule can be performed using less operations. The `--optimize-same-op` will remove these.

```bash
ruleprocessorY.exe -r rule.txt --optimize-same-op --hashcat-input > optimized_rule.txt
```
```tsv
$a      $b      ]
{       }       $b
[       *97     O57
T6      $n      O65
,0      ,6      Y4
```
The resulting rules could look like this, where operations that don't contribute have been removed:
```tsv
$a
$b
[   O57
$n  O65
,6  Y4
```

Finally we will look through all rules and find two rules that perform the same action. This can be a very computational intensive operation and requires 2-3x the size of the wordlist in RAM. A warning is displayed for this. An extra flag has been added to support large rule files, but will take exponentially long to complete.
`--optimize-similar-op` will perform the optimization, and `--optimize-slow` as an EXTRA flag, will utilize the memory-limited variant. Included is an example of a rule file before and after optimization. It will keep the rule with the least operations it comes across that performs change that has not been seen before. If two rules perform the same operations with the same actions it will take the first occurrence. 

Replace rules `s` that replace one word with another are skipped (`s/alpha/beta`), `s/a/beta` is taken into account.

```bash
ruleprocessorY.exe -r rule.txt --optimize-similar-op --hashcat-input > optimized_rule.txt
ruleprocessorY.exe -r rule.txt --optimize-all --hashcat-input > optimized_rule.txt
```
```tsv
$a  $b
$ab
$abc
$a  ^a
^a  $a
$$  Z2
$$  $$  $$
D1  $1  $2  $3  D0
$1  D0  $3  D0  $3
[   [   $1  $2  $3
$6  [   $9
[   $6  $9
```

The optimized version:
```tsv
$ab
$abc
$a  ^a
$$      Z2
[       [       $1      $2      $3
[       $6      $9
```

## Rule Optimizing / Comparison
Additionally, you can compare one rule against another and optimize rule files against each other. Removing rules from file A that also appear in file B. To do so we can use the `--optimize-compare` flag. Example command to remove all rules from fordy10k.txt that also appear in best64.rule.
```bash
ruleprocessorY.exe --hashcat-input --optimize-all -r fordy10k.txt --optimize-compare best64.rule
```

## Optimize debugging
To debug what changes have been made, the `--optimize-debug` flag can be used. This will display what changes are made to STDOUT.
Example output:
```yml
Before: $!      o9H     x27
After:  $!      x27
Before: $*      @*      +3
After:  @*      +3
Before: $/      @/      i3k
After:  @/      i3k
Before: $1      +7      D7
After:  $1      D7
Before: $1      D6      *45     '6
After:  $1      *45     '6
Before: $1      DA      @1
After:  DA      @1

Kept:   $$      Z2
Deleted:        $$      $$      $$
Kept:   D1      $1      $2      $3      D0
Deleted:        [       [       $1      $2      $3
Kept:   $6      [       $9
Deleted:        [       $6      $9
Kept:   $1      +0      Z1
Deleted:        +0      $1      $1
Kept:   o2a
Deleted:        $5      o2a     ]
Kept:   $3      $2      $1      D0
Deleted:        [       $3      $2      $1
Kept:   $2      $0      $1      $1      [
Deleted:        [       $2      $0      $1      $1
Kept:   $l      $o      $l
Deleted:        $l      $l      $o      K
```

The action when a new rule is added is not displayed to not overload the debug output. This can be re-enabled in the code by searching for "Kept new" in main.cpp
