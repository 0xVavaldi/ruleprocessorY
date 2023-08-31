#include <cstdio>
#include <cmath>
#include <string>
#include <cstring>
#include <vector>
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <sstream>
#include <thread>
#include <queue>
#include <mutex>
#include <set>
#include <condition_variable>
#include "rule.h"


inline bool file_exists (const std::string& file_name) {
    std::ifstream infile(file_name);
    return infile.good();
}

bool replace(std::string& str, const std::string& from, const std::string& to) {
    size_t start_pos = str.find(from);
    if(start_pos == std::string::npos)
        return false;
    str.replace(start_pos, from.length(), to);
    return true;
}

std::vector<std::string> split(const std::string& input_string, char delimiter) {
    std::vector<std::string> internal;
    std::stringstream ss(input_string); // Turn the string into a stream.
    std::string tok;

    while(getline(ss, tok, delimiter)) {
        internal.push_back(tok);
    }

    return internal;
}

bool sort_lineorder_rules(const std::pair<unsigned long ,std::vector<Rule>> &a, const std::pair<unsigned long ,std::vector<Rule>> &b)
{
    return (a.first < b.first);
}

static void show_usage() {
    std::cerr << "Usage: RuleProcessorY [option(s)] > results.rule\n"
    << "Options:\n"
    << "\t-h,--help\t\t\tShow this help message\n"
    << "\t-w,--wordlist WORDLIST_FILE\tSpecify the input wordlist path\n"
    << "\t-r,--rules RULE_FILE\t\tSpecify the input rules path\n"
    << "\t--delimiter DELIMITER\t\tSpecify delimiter to use. Default: \\t, Default hashcat: \" \"\n\n"
    << "\t--hashcat-input\t\t\tUse hashcat rule format for input rules\n"
    << "\t--hashcat-output\t\tUse hashcat rule format for the output of rules\n\n"
    << "\t--optimize-no-op\t\tRemove rules that perform no operation \"$1 ]\"\n"
    << "\t--optimize-same-op\t\tRemove rules that perform the same operation \"$1 $1 ]\" => \"$1\"\n"
    << "\t--optimize-similar-op\t\tRemove one of the rules that performs a similar operation \"$1 ^1\" and \"^1 $1\"\n"
    << "\t--optimize-all\t\t\tAll the optimizations!\n"
    << "\t--optimize-compare COMPARE_FILE\tRemove rules from RULE_FILE found in COMPARE_FILE (like similar-op)\n"
    << "\t--optimize-debug\t\tShow the modified rules in STDOUT\n"
    << "\t--optimize-slow\t\t\tDo not use memory to store data\n"
    << "\t--optimized-words\t\tLose cracks, but remove more rules. !USE_WITH_CAUTION!\n"
    << "Version: 1.2\n\n"
    << std::endl;
}

std::vector<std::thread> threads;
std::queue<std::vector<std::pair<unsigned long, std::vector<Rule>>>> rule_queue;
std::queue<std::vector<long long>> rule_queue_stage_3;
std::vector<std::pair<unsigned long, std::vector<Rule>>> queue_buffer;
std::mutex lock_obj;
std::mutex result_rule_mutex;
std::condition_variable condition_var;
std::vector<std::pair<unsigned long, std::vector<Rule>>> good_rule_objects;
std::vector<std::pair<unsigned long, std::vector<Rule>>> bad_rule_objects;
std::vector<std::pair<unsigned long, std::string>> ordered_comments;
int improvement_counter_level_2 = 0;
int duplicates_removed_level_3_compare = 0;
int duplicates_removed_level_3 = 0;
int redundant_removed = 0;
bool is_processing{true};
bool optimize_debug{false};
std::vector<std::string> invalid_lines;

// Convert from Hashcat to TSV format (for RuleProcessorY)
std::string convert_from_hashcat(unsigned long line_counter, std::string rule) {
    // sets of each rule width
    std::set<char> single_wide = { ':', 'l', 'u', 'c', 'C', 't', 'r', 'd', 'f', '{', '}', '[', ']', 'k', 'K', 'q','E' };
    std::set<char> double_wide = { 'T', 'p', 'D', 'Z', 'z', '$', '^', '<', '>', '_', '\'', '!', '/', '@' ,'-', '+', 'y', 'Y', 'L', 'R', '.', ',', 'e' };
    std::set<char> triple_wide = { 's', 'x', 'O', 'o', 'i', '*', '3' };
    std::string formatted_rule;
    int offset;
    char baseRule;
    formatted_rule = "";

    for (offset = 0; offset < rule.length();) {
        // get rule identifier
        baseRule = rule[offset];

        // skip if it's the space separator
        if (baseRule == ' ')
            offset += 1;

            // check if the rule is 1 character wide
        else if (single_wide.count(baseRule)) {
            formatted_rule += rule.substr(offset, 1) + '\t';
            offset += 1;
        }
            // check if the rule is 2 characters wide
        else if (double_wide.count(baseRule)) {
            // check for hex notation
            if (rule.substr(offset + 1, 2) == "\\x") {
                formatted_rule += rule.substr(offset, 5) + '\t';
                offset += 5;
            }
            else {
                formatted_rule += rule.substr(offset, 2) + '\t';
                offset += 2;
            }
        }
            // check if the rule is 3 characters wide
        else if (triple_wide.count(baseRule)) {
            // check for hex notation
            if (rule.substr(offset + 1, 2) == "\\x" || rule.substr(offset + 2, 2) == "\\x") {
                formatted_rule += rule.substr(offset, 6) + '\t';
                offset += 6;
            }
            else {
                formatted_rule += rule.substr(offset, 3) + '\t';
                offset += 3;
            }
        }
            // ignore if the line is a comment
        else if (baseRule == '#')
            offset = 254;
            // error if the baseRule is unknown
        else {
            std::cerr << "Unknown rule format on line " << line_counter << ": " << baseRule << ':' << rule << std::endl;
            offset = 254;
        }
    }
    return formatted_rule;
}

void process_stage1_thread(const std::vector<std::string>& test_words) {
    while(!rule_queue.empty() || is_processing) {
        std::unique_lock<std::mutex> lock(lock_obj);
        condition_var.wait(lock, [&] {
            return !(rule_queue.empty() && is_processing);
        });
        if (rule_queue.empty()) {
            lock.unlock();
            continue;
        }
        std::vector<std::pair<unsigned long, std::vector<Rule>>> rule_buffer = rule_queue.front();
        rule_queue.pop();
        lock.unlock();

        for(auto& rule_set_pair : rule_buffer) {
            bool changes_made = false;
            for (const std::string &test_word: test_words) {
                if (rule_set_pair.second[0].rule == ':') {
                    changes_made = true;
                    continue;
                }

                std::string new_plain{test_word};
                for (Rule &rule_item: rule_set_pair.second) {
                    rule_item.process(new_plain);
                }

                if (test_word != new_plain && !new_plain.empty()) {
                    changes_made = true;
                }
            }

            for (Rule &rule_item: rule_set_pair.second) {
                if (rule_item.rule == 's' && rule_item.rule_value_1 != rule_item.rule_value_2) {
                    changes_made = true;
                }
            }

            if (changes_made) {
                std::unique_lock<std::mutex> new_lock(result_rule_mutex); // Lock
                good_rule_objects.emplace_back(rule_set_pair);
                new_lock.unlock();
                continue;
            }
            // else
            redundant_removed++;
            if (optimize_debug) {
                std::unique_lock<std::mutex> new_lock(result_rule_mutex); // Lock
                std::cout << "Deleted:\t";
                for (int i = 0; i < rule_set_pair.second.size(); i++) {
                    rule_set_pair.second[i].print();
                    if (i != rule_set_pair.second.size() - 1) std::cout << '\t';
                }
                std::cout << std::endl;
                new_lock.unlock();
            }
        }
    }
}

void process_stage2_thread(const std::vector<std::string>& test_words) {
    // todo investigate why threading occasionally hangs / pause and does not close correctly. Causing a deadlock
    while(!rule_queue.empty() || is_processing) {
        std::unique_lock<std::mutex> lock(lock_obj);
        condition_var.wait(lock, [&] {
            return !(rule_queue.empty() && is_processing);
        });
        if(rule_queue.empty()) {
            lock.unlock();
            continue;
        }
        std::vector<std::pair<unsigned long, std::vector<Rule>>> rule_buffer = rule_queue.front();
        rule_queue.pop();
        lock.unlock();

        for(auto& rule_set_pair : rule_buffer) {
            // Create PowerSet
            double pow_set_size = pow(2, rule_set_pair.second.size());
            int counter, j;
            bool found_new = false;

            // Get original rule output to compare against powerset output
            std::vector<std::string> original_rule_output;
            for (const std::string &test_word: test_words) {
                std::string new_plain{test_word};
                for (Rule &rule_item: rule_set_pair.second) {
                    rule_item.process(new_plain);
                }

                if (test_word != new_plain && !new_plain.empty()) {
                    original_rule_output.push_back(std::move(new_plain));
                }
            }
            // End fetching original rule output

            for (counter = 0; counter < pow_set_size; counter++) {
                std::vector<Rule> rule_power_set_item;
                for (j = 0; j < rule_set_pair.second.size(); j++) {
                    if (counter & (1 << j))
                        rule_power_set_item.emplace_back(rule_set_pair.second[j]);
                }
                if(rule_power_set_item.size() > 1 && rule_power_set_item.size() < rule_set_pair.second.size()) {
                    // start testing
                    std::vector<std::string> powerset_item_output;
                    for (const std::string &test_word: test_words) {
                        std::string new_plain{test_word};
                        for (Rule &rule_item: rule_power_set_item) {
                            rule_item.process(new_plain);
                        }
                        if (test_word != new_plain && !new_plain.empty()) {
                            powerset_item_output.push_back(std::move(new_plain));
                        }
                    }
                    if (original_rule_output == powerset_item_output) {
                        // Do not modify if the rule_value_1 is greater than 1 char due to test-set not covering those cases.
                        bool modify = true;
                        for (const Rule &rule_item: rule_set_pair.second) {
                            if (Rule::rule_identify(rule_item.rule) == 3 && rule_item.rule_value_1.size() > 1) {
                                modify = false;
                            }
                        }

                        if (modify) {
                            found_new = true;
                            std::unique_lock<std::mutex> new_lock(result_rule_mutex); // Lock
                            if(optimize_debug) {
                                std::cout << "Before:\t";
                                for (Rule rule: rule_set_pair.second) {
                                    rule.print();
                                    std::cout << '\t';
                                }

                                std::cout << std::endl;
                                std::cout << "After:\t";
                                for (Rule rule: rule_power_set_item) {
                                    rule.print();
                                    std::cout << '\t';
                                }
                                std::cout << std::endl;
                            }
                            // Add improved / optimized rule
                            std::pair<unsigned long, std::vector<Rule>> improved_pair (rule_set_pair.first, std::move(rule_power_set_item));
                            good_rule_objects.push_back(improved_pair);
                            improvement_counter_level_2++;
                            new_lock.unlock(); // Unlock
                            break;
                        }
                    }
                }
            }

            if(!found_new) {
                // keep old rule
                std::unique_lock<std::mutex> new_lock(result_rule_mutex); // Lock
                good_rule_objects.push_back(std::move(rule_set_pair));
                new_lock.unlock(); // Unlock
            }
            // end of buffer
        }
        //finalize
    }
}

long double get_rule_performance(const Rule& rule) {
    // obtained by testing on a single NVIDIA 3070v1
    // perl -e 'print "D4\n" x 200000' > rule       (rule to test)
    // ./hashcat --potfile-disable -m900 afe04867ec7a3845145579a95f72e000 -O D:\Wordlists\rockyou.txt -r rule -n 64 -u 256 -T 512 --backend-vector-width 1 --force
    // Take the GH/s value, one decimal place rounded to nearest quarter

    switch(rule.rule) {
        case ':':
            return 25;
        case 'l':
            return 16.5;
        case 'u':
            return 16.75;
        case 'c':
            return 16;
        case 'C':
            return 15.75;
        case 't':
            return 16;
        case 'T':
            return 19.5;
        case 'r':
            return 16.25;
        case 'd':
            return 18;
        case 'p': // pA
            return 21.5;
        case 'f':
            return 14.5;
        case '{':
            return 20;
        case '}':
            return 19.5;
        case '$': // $a
            return 22.75;
        case '^': // ^a
            return 21.0;
        case '[':
            return 22.75;
        case ']':
            return 21;
        case 'D':
            return 21.75;
        case 'x': // x46
            return 19.75;
        case 'O': // O31
            return 20.5;
        case 'i': // i4c
            return 19;
        case 'o': // o5e
            return 19.5;
        case '\'': // 5'
            return 20;
        case 's':
            return 11.5;
        case '@': // this one can go from 10-15 GH/s quite easily by choosing e or x respectively.
            return 10.25;
        case 'z':
            return 18.75;
        case 'Z':
            return 9.75;
        case 'q':
            return 18.5;
        case 'k':
            return 20.5;
        case 'K':
            return 19.75;
        case '*':
            return 19.5;
        case 'L': // L4
            return 19.75;
        case 'R': // R4
            return 19.75;
        case '+': // +4
            return 19.75;
        case '-': // -4
            return 19.75;
        case '.': // .4
            return 10;
        case ',': // ,4
            return 10;
        case 'y': // y4
            return 17.75;
        case 'Y': // Y4
            return 18;
        case 'E':
            return 11.5;
        case 'e': // e-
            return 11;
        case '3': // 30-
            return 14.5;
    }
    return 15; // default a bit in the middle (lower end)
}

void process_stage3_thread(std::vector<std::pair<unsigned long, std::vector<Rule>>>& all_rules, const std::vector<std::vector<std::string>>& all_rules_output, const std::vector<std::vector<std::string>>& all_compare_rules_output, bool optimize_similar_op) {
    while(!rule_queue_stage_3.empty() || is_processing) {
        std::unique_lock<std::mutex> lock(lock_obj);
        condition_var.wait(lock, [&] {
            return !(rule_queue_stage_3.empty() && is_processing);
        });
        if (rule_queue_stage_3.empty()) {
            lock.unlock();
            continue;
        }

        std::vector<long long> buffer = rule_queue_stage_3.front();
        rule_queue_stage_3.pop();
        lock.unlock();
        for (long long rule_iterator: buffer) { // Enumerate the buffer
            std::pair<unsigned long, std::vector<Rule>> &rule_set_pair = all_rules[rule_iterator];
            if(all_rules.size() < 2) { // Skip if too small
                std::unique_lock<std::mutex> new_lock(result_rule_mutex); // Lock
                good_rule_objects.push_back(std::move(rule_set_pair));
                new_lock.unlock();
                continue;
            }

            // Get rule set output from every other rule set
            bool matches_none = true;
            if(!all_compare_rules_output.empty()) { // if comparing to another rule-set
                bool is_bad = false;
                for (const auto & i : all_compare_rules_output) {
                    // Compare output from ruleset with comparison ruleset and if matches, do not save rule (i.e. delete it)
                    if (all_rules_output[rule_iterator] == i) {
                        // if good_rule_objects contains rule_set then skip
                        matches_none = false;
                        duplicates_removed_level_3_compare++;

                        std::unique_lock<std::mutex> new_lock(result_rule_mutex); // Lock
                        if(optimize_debug) {
                            std::cout << std::endl;
                            std::cout << "Deleted:\t";
                            for(int j = 0; j < all_rules[rule_iterator].second.size(); j++) {
                                all_rules[rule_iterator].second[j].print();
                                if(j != all_rules[rule_iterator].second.size()-1) std::cout << '\t';
                            }
                            std::cout << std::endl;
                        }
                        bad_rule_objects.push_back(std::move(rule_set_pair));
                        new_lock.unlock();
                    }
                }

                if(!optimize_similar_op) { // skip if not intending to optimize the main file too.
                    if (matches_none) {
                        std::unique_lock<std::mutex> good_lock(result_rule_mutex);
                        good_rule_objects.emplace_back(rule_set_pair);
                        good_lock.unlock();
                    }
                    continue;
                }
            }


            // Comparing to itself, if no comparison rule is set
            for (size_t i = 0; i < all_rules.size(); i++) {
                // Compare output from ruleset with comparison ruleset
                if (all_rules_output[rule_iterator] == all_rules_output[i] && i != rule_iterator) {
                    // if good_rule_objects contains rule_set -> skip
                    std::pair<unsigned long, std::vector<Rule>> &rule_set_comparison_pair = all_rules[i];
                    matches_none = false;
                    bool rule_set_is_good = false;
                    std::unique_lock<std::mutex> good_lock(result_rule_mutex);
                    if (std::find(good_rule_objects.begin(), good_rule_objects.end(), rule_set_pair) != good_rule_objects.end()) { // if original rule is good, investigate. Comparison might need to be replaced or removed.
                        rule_set_is_good = true;
                    }
                    if (std::find(bad_rule_objects.begin(), bad_rule_objects.end(), rule_set_pair) != bad_rule_objects.end()) { // if original rule is bad, a good one already exists -> skip
                        good_lock.unlock();
                        continue;
                    }
                    if (std::find(bad_rule_objects.begin(), bad_rule_objects.end(), rule_set_comparison_pair) != bad_rule_objects.end()) { // if comparison is bad, a good one already exists -> skip
                        good_lock.unlock();
                        continue;
                    }
                    if (std::find(good_rule_objects.begin(), good_rule_objects.end(), rule_set_comparison_pair) != good_rule_objects.end()) { // if comparison is good -> skip. We only need to logically go through one condition
                        good_lock.unlock();
                        continue;
                    }
                    duplicates_removed_level_3++;

                    // save smaller size
                    if (rule_set_pair.second.size() < rule_set_comparison_pair.second.size()) {
                        // Set rule_set_pair line number to be the lowest of the two since they're identical outputs.
                        rule_set_pair.first = (rule_set_pair.first < rule_set_comparison_pair.first) ? rule_set_pair.first : rule_set_comparison_pair.first;
                        if (rule_set_is_good) { // if the rule_set is not already part of the good_rules, add it
                            bad_rule_objects.emplace_back(rule_set_comparison_pair);
                        } else {
                            good_rule_objects.emplace_back(rule_set_pair);
                            bad_rule_objects.emplace_back(rule_set_comparison_pair);
                        }
                        if (optimize_debug) {
                            if(!rule_set_is_good) std::cout << "Kept:\t\t";
                            if(rule_set_is_good) std::cout << "Exists:\t\t";
                            for (int j = 0; j < rule_set_pair.second.size(); j++) {
                                rule_set_pair.second[j].print();
                                if (j != rule_set_pair.second.size() - 1) std::cout << '\t';
                            }
                            std::cout << std::endl;
                            std::cout << "Deleted:\t";
                            for (int j = 0; j < rule_set_comparison_pair.second.size(); j++) {
                                rule_set_comparison_pair.second[j].print();
                                if (j != rule_set_comparison_pair.second.size() - 1) std::cout << '\t';
                            }
                            std::cout << std::endl;
                        }
                        good_lock.unlock();
                        continue;
                    }

                    // Don't save the larger rule
                    if(rule_set_pair.second.size() > rule_set_comparison_pair.second.size()) {
                        // Set rule_set_comparison_pair line number to be the lowest of the two since they're identical outputs.
                        rule_set_comparison_pair.first = (rule_set_comparison_pair.first < rule_set_pair.first) ? rule_set_comparison_pair.first : rule_set_pair.first;
                        if (rule_set_is_good) { // rule set is already good
                            // Remove rule_set_pair from the list.
                            good_rule_objects.erase(std::remove(good_rule_objects.begin(), good_rule_objects.end(), rule_set_pair), good_rule_objects.end());
                            // Add comparison pair to good objects instead
                            good_rule_objects.emplace_back(rule_set_comparison_pair);
                            bad_rule_objects.emplace_back(rule_set_pair);
                        } else { // rule set is not good
                            good_rule_objects.emplace_back(rule_set_comparison_pair);
                            bad_rule_objects.emplace_back(rule_set_pair);
                        }
                        if(optimize_debug) {
                            if(!rule_set_is_good) std::cout << "Kept:\t\t";
                            if(rule_set_is_good) std::cout << "Exists:\t\t";
                            for (int j = 0; j < rule_set_comparison_pair.second.size(); j++) {
                                rule_set_comparison_pair.second[j].print();
                                if (j != rule_set_comparison_pair.second.size() - 1) std::cout << '\t';
                            }
                            std::cout << std::endl;
                            std::cout << "Deleted:\t";
                            for (int j = 0; j < rule_set_pair.second.size(); j++) {
                                rule_set_pair.second[j].print();
                                if (j != rule_set_pair.second.size() - 1) std::cout << '\t';
                            }
                            std::cout << std::endl;
                        }
                        good_lock.unlock();
                        continue;
                    }

                    // Compare complexity and choose faster one.
                    if(rule_set_pair.second.size() == rule_set_comparison_pair.second.size()) { // if they're the same length, judge what is better efficiency
                        long double rule_performance = 0;
                        long double rule_comparison_performance = 0;
                        for(const auto& rule_item : rule_set_pair.second) {
                            rule_performance += get_rule_performance(rule_item);
                        }
                        for(const auto& rule_item : rule_set_comparison_pair.second) {
                            rule_comparison_performance += get_rule_performance(rule_item);
                        }

                        if(rule_performance >= rule_comparison_performance) {
                            rule_set_pair.first = (rule_set_pair.first < rule_set_comparison_pair.first) ? rule_set_pair.first : rule_set_comparison_pair.first;
                            if(rule_set_is_good) {
                                bad_rule_objects.emplace_back(rule_set_comparison_pair);
                            } else {
                                // Set rule_set_pair line number to be the lowest of the two since they're identical outputs.
                                good_rule_objects.emplace_back(rule_set_pair);
                                bad_rule_objects.emplace_back(rule_set_comparison_pair);
                            }
                            if(optimize_debug) {
                                if(!rule_set_is_good) std::cout << "Kept:\t\t";
                                if(rule_set_is_good) std::cout << "Exists:\t\t";
                                    for (int j = 0; j < rule_set_pair.second.size(); j++) {
                                        rule_set_pair.second[j].print();
                                        if (j != rule_set_pair.second.size() - 1) std::cout << '\t';
                                    }
                                    std::cout << std::endl;
                                std::cout << "Deleted:\t";
                                for (int j = 0; j < rule_set_comparison_pair.second.size(); j++) {
                                    rule_set_comparison_pair.second[j].print();
                                    if (j != rule_set_comparison_pair.second.size() - 1) std::cout << '\t';
                                }
                                std::cout << std::endl;
                            }
                        } else {
                            rule_set_comparison_pair.first = (rule_set_comparison_pair.first < rule_set_pair.first) ? rule_set_comparison_pair.first : rule_set_pair.first;
                            if(rule_set_is_good) {
                            // Set rule_set_comparison_pair line number to be the lowest of the two since they're identical outputs.
                                good_rule_objects.erase(std::remove(good_rule_objects.begin(), good_rule_objects.end(), rule_set_pair), good_rule_objects.end());
                                good_rule_objects.emplace_back(rule_set_comparison_pair);
                                bad_rule_objects.emplace_back(rule_set_pair);
                            } else {
                                good_rule_objects.emplace_back(rule_set_comparison_pair);
                                bad_rule_objects.emplace_back(rule_set_pair);
                            }

                            if(optimize_debug) {
                                std::cout << "Kept:\t\t";
                                for (int j = 0; j < rule_set_comparison_pair.second.size(); j++) {
                                    rule_set_comparison_pair.second[j].print();
                                    if (j != rule_set_comparison_pair.second.size() - 1) std::cout << '\t';
                                }
                                std::cout << std::endl;
                                std::cout << "Deleted:\t";
                                for (int j = 0; j < rule_set_pair.second.size(); j++) {
                                    rule_set_pair.second[j].print();
                                    if (j != rule_set_pair.second.size() - 1) std::cout << '\t';
                                }
                                std::cout << std::endl;
                            }
                        }
                        good_lock.unlock();
                        continue;
                    }
                }
            }

            // default behaviour if nothing matches and it's unique
            if (matches_none) {
                std::unique_lock<std::mutex> new_lock(result_rule_mutex); // Lock
                good_rule_objects.emplace_back(rule_set_pair);
                new_lock.unlock();
            }
        }
    }
}

void process_stage3_thread_slow(std::vector<std::pair<unsigned long, std::vector<Rule>>>& all_rules, std::vector<std::pair<unsigned long, std::vector<Rule>>>& all_compare_rules, const std::vector<std::string>& test_words, bool optimize_similar_op) {
    // todo possible rewrite to check feasibility of file memory
    while(!rule_queue_stage_3.empty() || is_processing) {
        std::unique_lock<std::mutex> lock(lock_obj);
        condition_var.wait(lock, [&] {
            return !(rule_queue_stage_3.empty() && is_processing);
        });
        if (rule_queue_stage_3.empty()) {
            lock.unlock();
            continue;
        }

        std::vector<long long> buffer = rule_queue_stage_3.front();
        rule_queue_stage_3.pop();
        lock.unlock();
        for (long long rule_iterator: buffer) {
            std::pair<unsigned long, std::vector<Rule>> &rule_set_pair = all_rules[rule_iterator];
            if(all_rules.size() < 2) { // Skip if too small
                std::unique_lock<std::mutex> new_lock(result_rule_mutex); // Lock
                good_rule_objects.emplace_back(rule_set_pair);
                new_lock.unlock();
                continue;
            }

            std::vector<std::string> rule_set_output;
            rule_set_output.reserve(test_words.size());
            for (const std::string &test_word: test_words) {
                std::string new_plain{test_word};
                for (Rule &rule_item: rule_set_pair.second) {
                    rule_item.process(new_plain);
                }
                if (test_word != new_plain && !new_plain.empty()) {
                    rule_set_output.push_back(std::move(new_plain));
                }
            }

            // Get rule set output from every other rule set
            bool matches_none = true;
            if(!all_compare_rules.empty()) { // if comparing to another rule-set
                for (size_t i = 0; i < all_compare_rules.size(); i++) {
                    std::vector<std::string> compare_rule_set_output;
                    compare_rule_set_output.reserve(test_words.size());
                    std::vector<Rule> &rule_set_comparison = all_compare_rules[i].second;

                    // Get the computed words
                    for (const std::string &test_word: test_words) {
                        std::string new_plain{test_word};
                        for (Rule &rule_item: rule_set_comparison) {
                            rule_item.process(new_plain);
                        }
                        if (test_word != new_plain && !new_plain.empty()) {
                            compare_rule_set_output.push_back(std::move(new_plain));
                        }
                    }
                    // Compare output from ruleset with comparison ruleset and if matches, do not save rule (i.e. delete it)
                    if (rule_set_output == compare_rule_set_output) {
                        // if good_rule_objects contains rule_set -> skip
                        matches_none = false;
                        duplicates_removed_level_3_compare++;

                        std::unique_lock<std::mutex> new_lock(result_rule_mutex); // Lock
                        if(optimize_debug) {
                            std::cout << "Deleted:\t";
                            for(int j = 0; j < all_rules[i].second.size(); j++) {
                                all_rules[i].second[j].print();
                                if(j != all_rules[i].second.size()-1) std::cout << '\t';
                            }
                            std::cout << std::endl;
                        }
                        bad_rule_objects.emplace_back(rule_set_pair);
                        new_lock.unlock();
                    }
                }

                if(!optimize_similar_op) { // skip if not intending to optimize the main file too.
                    if (matches_none) {
                        std::unique_lock<std::mutex> good_lock(result_rule_mutex);
                        good_rule_objects.emplace_back(rule_set_pair);
                        good_lock.unlock();
                    }
                    continue;
                }
            }

            // Compare rules to itself (O(x^2))
            for (size_t i = 0; i < all_rules.size(); i++) {
                std::unique_lock<std::mutex> good_lock(result_rule_mutex);
                std::pair<unsigned long, std::vector<Rule>> &rule_set_comparison_pair = all_rules[i];
                if (std::find(bad_rule_objects.begin(), bad_rule_objects.end(), rule_set_pair) != bad_rule_objects.end()) { // if original rule is bad, a good one already exists -> skip
                    good_lock.unlock();
                    continue;
                }
                if (std::find(bad_rule_objects.begin(), bad_rule_objects.end(), rule_set_comparison_pair) != bad_rule_objects.end()) { // if comparison is bad, a good one already exists -> skip
                    good_lock.unlock();
                    continue;
                }
                if (std::find(good_rule_objects.begin(), good_rule_objects.end(), rule_set_comparison_pair) != good_rule_objects.end()) { // if comparison is good -> skip. We only need to logically go through one condition
                    good_lock.unlock();
                    continue;
                }


                std::vector<std::string> compare_rule_set_output;
                compare_rule_set_output.reserve(test_words.size());

                for (const std::string &test_word: test_words) {
                    std::string new_plain{test_word};
                    for (Rule &rule_item: rule_set_comparison_pair.second) {
                        rule_item.process(new_plain);
                    }
                    if (test_word != new_plain && !new_plain.empty()) {
                        compare_rule_set_output.push_back(std::move(new_plain));
                    }
                }
                // Compare output from ruleset with comparison ruleset
                if (rule_set_output == compare_rule_set_output && i != rule_iterator) {
                    // if the rule output is the same, but the rule is different
                    matches_none = false;
                    bool rule_set_is_good = false;
                    // if rule_set_pair is in good_rule_objects or bad_rule_objects -> skip
                    if (std::find(good_rule_objects.begin(), good_rule_objects.end(), rule_set_pair) != good_rule_objects.end()) { // if original rule is good, investigate. Comparison might need to be replaced or removed.
                        rule_set_is_good = true;
                    }
                    duplicates_removed_level_3++;

                    // save the smaller rule
                    if(rule_set_pair.second.size() < rule_set_comparison_pair.second.size()) { // if one rule is smaller than the other, take it
                        rule_set_pair.first = (rule_set_pair.first < rule_set_comparison_pair.first) ? rule_set_pair.first : rule_set_comparison_pair.first;
                        if (rule_set_is_good) { // if the rule_set is not already part of the good_rules, add it
                            bad_rule_objects.emplace_back(rule_set_comparison_pair);
                        } else {
                            good_rule_objects.emplace_back(rule_set_pair);
                            bad_rule_objects.emplace_back(rule_set_comparison_pair);
                        }
                        good_lock.unlock();
                        if(optimize_debug) {
                            if(!rule_set_is_good) std::cout << "Kept:\t\t";
                            if(rule_set_is_good) std::cout << "Exists:\t";
                            for (int j = 0; j < rule_set_pair.second.size(); j++) {
                                rule_set_pair.second[j].print();
                                if (j != rule_set_pair.second.size() - 1) std::cout << '\t';
                            }
                            std::cout << std::endl;
                            std::cout << "Deleted:\t";
                            for(int j = 0; j < all_rules[i].second.size(); j++) {
                                all_rules[i].second[j].print();
                                if(j != all_rules[i].second.size()-1) std::cout << '\t';
                            }
                            std::cout << std::endl;
//                        }
                        }
                        continue;
                    }

                    // Don't save the larger rule
                    if(rule_set_pair.second.size() > rule_set_comparison_pair.second.size()) {
                        rule_set_comparison_pair.first = (rule_set_comparison_pair.first < rule_set_pair.first) ? rule_set_comparison_pair.first : rule_set_pair.first;
                        if (rule_set_is_good) { // rule set is already good
                            // Remove rule_set_pair from the list.
                            good_rule_objects.erase(std::remove(good_rule_objects.begin(), good_rule_objects.end(), rule_set_pair), good_rule_objects.end());
                            // Add comparison pair to good objects instead
                            good_rule_objects.emplace_back(rule_set_comparison_pair);
                            bad_rule_objects.emplace_back(rule_set_pair);
                        } else { // rule set is not good
                            good_rule_objects.emplace_back(rule_set_comparison_pair);
                            bad_rule_objects.emplace_back(rule_set_pair);
                        }
                        good_lock.unlock();
                        if(optimize_debug) {
                            if(rule_set_is_good) { // rule set is already good
                                std::cout << "Exists:\t";
                                for (int j = 0; j < rule_set_pair.second.size(); j++) {
                                    rule_set_pair.second[j].print();
                                    if (j != rule_set_pair.second.size() - 1) std::cout << '\t';
                                }
                                std::cout << std::endl;
                                std::cout << "Deleted:\t";
                                for (int j = 0; j < rule_set_comparison_pair.second.size(); j++) {
                                    rule_set_comparison_pair.second[j].print();
                                    if (j != rule_set_comparison_pair.second.size() - 1) std::cout << '\t';
                                }
                                std::cout << std::endl;
                            } else {
                                std::cout << "Kept:\t";
                                for (int j = 0; j < rule_set_comparison_pair.second.size(); j++) {
                                    rule_set_comparison_pair.second[j].print();
                                    if (j != rule_set_comparison_pair.second.size() - 1) std::cout << '\t';
                                }
                                std::cout << std::endl;
                                std::cout << "Deleted:\t";
                                for (int j = 0; j < rule_set_pair.second.size(); j++) {
                                    rule_set_pair.second[j].print();
                                    if (j != rule_set_pair.second.size() - 1) std::cout << '\t';
                                }
                                std::cout << std::endl;
                            }
                        }
                        continue;
                    }

                    // Compare complexity and choose faster one.
                    if(rule_set_pair.second.size() == rule_set_comparison_pair.second.size()) { // if they're the same length, judge what is better efficiency
                        long double rule_performance = 0;
                        long double rule_comparison_performance = 0;
                        for(const auto& rule_item : rule_set_pair.second) {
                            rule_performance += get_rule_performance(rule_item);
                        }
                        for(const auto& rule_item : rule_set_comparison_pair.second) {
                            rule_comparison_performance += get_rule_performance(rule_item);
                        }

                        if(rule_performance >= rule_comparison_performance) {
                            rule_set_pair.first = (rule_set_pair.first < rule_set_comparison_pair.first) ? rule_set_pair.first : rule_set_comparison_pair.first;
                            if(rule_set_is_good) {
                                bad_rule_objects.emplace_back(rule_set_comparison_pair);
                            } else {
                                good_rule_objects.emplace_back(rule_set_pair);
                                bad_rule_objects.emplace_back(rule_set_comparison_pair);
                            }
                        } else {
                            rule_set_comparison_pair.first = (rule_set_comparison_pair.first < rule_set_pair.first) ? rule_set_comparison_pair.first : rule_set_pair.first;
                            if(rule_set_is_good) {
                                good_rule_objects.erase(std::remove(good_rule_objects.begin(), good_rule_objects.end(), rule_set_pair), good_rule_objects.end());
                                good_rule_objects.emplace_back(rule_set_comparison_pair);
                                bad_rule_objects.emplace_back(rule_set_pair);
                            } else {
                                good_rule_objects.emplace_back(rule_set_comparison_pair);
                                bad_rule_objects.emplace_back(rule_set_pair);
                            }
                        }
                        if(optimize_debug) {
                            if(!rule_set_is_good) std::cout << "Kept:\t\t";
                            if(rule_set_is_good) std::cout << "Exists:\t";
                            for (int j = 0; j < rule_set_pair.second.size(); j++) {
                                rule_set_pair.second[j].print();
                                if (j != rule_set_pair.second.size() - 1) std::cout << '\t';
                            }
                            std::cout << std::endl;
                            std::cout << "Deleted:\t";
                            for(int j = 0; j < all_rules[i].second.size(); j++) {
                                all_rules[i].second[j].print();
                                if(j != all_rules[i].second.size()-1) std::cout << '\t';
                            }
                            std::cout << std::endl;
                        }
                        good_lock.unlock();
                        continue;
                    }
                    continue;
                }
            }

            // default behaviour if nothing matches and it's unique
            if (matches_none) {
                std::unique_lock<std::mutex> new_lock(result_rule_mutex); // Lock
                good_rule_objects.emplace_back(rule_set_pair);
                new_lock.unlock();
            }
        }
    }
}


int main(int argc, const char *argv[]) {
    if (argc < 2) {
        show_usage();
        return 1;
    }

    std::string input_wordlist;
    std::string input_rules;
    std::string compare_rules;
    char delimiter = '\t';
    bool no_delimiter = false;
    bool help{false};
    bool optimize_slow{false};
    bool optimize_no_op{false};
    bool optimize_same_op{false};
    bool optimize_similar_op{false};
    bool hashcat_input{false};
    bool hashcat_output{false};
    bool optimized_words{false};
    std::ios_base::sync_with_stdio(false); // unsync the IO of C and C++
    time_t absolute_start;
    time(&absolute_start);

    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--wordlist" || std::string(argv[i]) == "-w") {
            if (i + 1 < argc && argv[i+1][0] != '-' && strlen(argv[i+1]) > 0) {
                input_wordlist = argv[i+1];
            } else {
                std::cerr << argv[i] << " option requires an argument." << std::endl;
                return -1;
            }
        }
        if (std::string(argv[i]) == "--rule" || std::string(argv[i]) == "-r") {
            if (i + 1 < argc && argv[i+1][0] != '-' && strlen(argv[i+1]) > 0) {
                input_rules = argv[i+1];
            } else {
                std::cerr << argv[i] << " option requires an argument." << std::endl;
                return -1;
            }
        }
        if (std::string(argv[i]) == "--help" || std::string(argv[i]) == "-h") {
            help = true;
        }

        if (std::string(argv[i]) == "--hashcat-input") {
            hashcat_input = true;
        }

        if (std::string(argv[i]) == "--hashcat-output") {
            hashcat_output = true;
        }
        // OPTIMIZE FLAGS
        if (std::string(argv[i]) == "--optimize-no-op") { //stage 1
            optimize_no_op = true;
        }
        if (std::string(argv[i]) == "--optimize-same-op") { // stage 2
            optimize_same_op = true;
        }
        if (std::string(argv[i]) == "--optimize-similar-op") { // stage 3
            optimize_similar_op = true;
        }
        if (std::string(argv[i]) == "--optimize-all") {
            optimize_no_op = true; // stage 1
            optimize_same_op = true; //stage 2
            optimize_similar_op = true; //stage 3
        }

        if (std::string(argv[i]) == "--optimize-compare") {
            if (i + 1 < argc && argv[i+1][0] != '-' && strlen(argv[i+1]) > 0) {
                if(!optimize_similar_op) std::cerr << "--optimize-compare has automatically enabled --optimize-similar-op." << std::endl;
                std::cerr << "--optimize-compare will not check the original file." << std::endl;

                compare_rules = argv[i+1];
            } else {
                std::cerr << argv[i] << " option requires an argument." << std::endl;
                return -1;
            }
        }

        if (std::string(argv[i]) == "--delimiter") {
            if (i + 1 < argc && argv[i+1][0] != '-' && strlen(argv[i+1]) > 0) {
                if(strlen(argv[i+1]) > 1) {
                    std::cerr << argv[i] << " delimiter must be at most 1 character." << std::endl;
                    return -1;
                }
                delimiter = argv[i + 1][0];
            } else {
                no_delimiter = true;
            }
        }

        // END OPTIMIZE FLAGS
        if (std::string(argv[i]) == "--optimize-debug") {
            optimize_debug = true;
            std::cerr << "Enabled Debugging" << std::endl;
        }
        if (std::string(argv[i]) == "--optimize-slow") {
            optimize_slow = true;
            std::cerr << "You are running slow mode, this can take forever and a day - be warned." << std::endl << "Computation time is exponentially larger in return for less RAM usage and should only be used as a last resort." <<  std::endl;
        }
        if (std::string(argv[i]) == "--optimized-words") {
            optimized_words = true;
            std::cerr << "Optimized words enabled. This can reduce your crack-rate!" << std::endl;
        }
    }

    if(help) {
        show_usage();
        return 1;
    }

    if(!(optimize_no_op || optimize_same_op || optimize_similar_op || !compare_rules.empty()) && (input_wordlist.empty() || input_rules.empty())) {
        show_usage();
        return 1;
    }

    std::vector<std::pair<unsigned long, std::vector<Rule>>> rule_objects;

    if(!input_wordlist.empty() && !file_exists(input_wordlist)) {
        fprintf(stderr, "Wordlist file error: \"%s\" does not exist.\n", input_wordlist.c_str());
        exit(EXIT_FAILURE);
    }
    if(!(optimize_no_op || optimize_same_op || optimize_similar_op) && optimized_words) {
        fprintf(stderr, "Optimized words specified, but not optimizing. Did you forget to add/remove a flag?\n");
        exit(EXIT_FAILURE);
    }
    if(!file_exists(input_rules)) {
        fprintf(stderr, "Rule file error: \"%s\" does not exist.\n", input_rules.c_str());
        exit(EXIT_FAILURE);
    }
    if(!compare_rules.empty() && !file_exists(compare_rules)) {
        fprintf(stderr, "Rule file error: \"%s\" does not exist.\n", input_rules.c_str());
        exit(EXIT_FAILURE);
    }
    if(optimized_words && !input_wordlist.empty()) {
        fprintf(stderr, "Can not use an optimized wordlist & a custom wordlist at the same time.\n");
        exit(EXIT_FAILURE);
    }

    // READ RULES FILE
    std::string line;
    std::ifstream rule_file_handle(input_rules);
    unsigned long line_counter = 1;
    std::cerr << "Started parsing rules" << std::endl;
    while (std::getline(rule_file_handle, line)) {
        if(line[0] == '#') {
            std::pair<unsigned long, std::string> comment {line_counter, line};
            ordered_comments.push_back(std::move(comment));
            line_counter++;
            continue;
        }
        if(line.size() >= 2 && line[0] == ' ' && line[1] == '#') {
            std::pair<unsigned long, std::string> comment {line_counter, line};
            ordered_comments.push_back(std::move(comment));
            line_counter++;
            continue;
        }
        if(hashcat_input) {
            line = convert_from_hashcat(line_counter, line);
        }
        std::string unescaped_line;
        // Unescape
        // Parse escaped hex chars
        for(int i=0; i < line.size(); i++) {
            if (i+3 < line.size() && line[i] == '\\' && line[i + 1] == 'x') {
                if (isxdigit(line[i + 2]) && isxdigit(line[i + 3])) {
                    int hi = int(line[i + 2]) - 48;
                    if (hi > 10) hi -= 7;
                    if (hi > 15) hi -= 32;

                    int low = int(line[i + 3]) - 48;
                    if (low > 10) low -= 7;
                    if (low > 15) low -= 32;

                    int value = ((int) hi) * 16 + (int)low;
                    unescaped_line += std::string(1, char(value));
                    i+=2;
                }
            } else {
                unescaped_line += line[i];
            }
        }

        std::vector<Rule> rule_set;
        std::vector<std::string> raw_rules;
        if(hashcat_input) {
            raw_rules = split(line, '\t');
        } else {
            raw_rules = split(line, delimiter);
        }
        bool is_valid = true;
        int i = 0;
        for(std::string raw_rule : raw_rules) {
            if(raw_rule.empty()) continue;
            char rule;
            std::string rule_value;
            std::string rule_value_2;
            i++;
            if(i % 100000 == 0) {
                std::cerr << "Parsed " << i << " rules" << std::endl;
            }

            if(Rule::rule_identify(raw_rule[0]) == 1) {
                rule = raw_rule[0];
                Rule single_rule(static_cast<char>(rule), "", "");
                rule_set.push_back(single_rule);
                continue;
            }

            if(Rule::rule_identify(raw_rule[0]) == 2 && raw_rule.size() >= 2) {
                rule = raw_rule[0];
                rule_value = raw_rule.substr(1, raw_rule.size());
                Rule single_rule(static_cast<char>(rule), rule_value, "");
                rule_set.push_back(single_rule);
                continue;
            }

            if(Rule::rule_identify(raw_rule[0]) == 3 && raw_rule.size() >= 3) {
                rule = raw_rule[0];
                rule_value = raw_rule[1];
                rule_value_2 = raw_rule.substr(2, raw_rule.size());
                if(count(raw_rule.begin(),raw_rule.end(),'/') >= 2) {
                    replace(raw_rule, "\\/", "\xFF\xFF"); // Fix escaped \/ to /
                    std::vector<std::string> raw_rule_parts = split(raw_rule, '/'); // Fix escaped \/ to /
                    for(auto &raw_rule_part : raw_rule_parts) {
                        replace(raw_rule_part, "\xFF\xFF", "/"); // Fix escaped \/ to /
                    }

                    rule_value = raw_rule_parts[1];
                    rule_value_2 = (raw_rule_parts.size() == 2) ? "" : raw_rule_parts[2];
                    Rule single_rule(static_cast<char>(rule), rule_value, rule_value_2);
                    rule_set.push_back(single_rule);
                } else {
                    Rule single_rule(static_cast<char>(rule), rule_value, rule_value_2);
                    rule_set.push_back(single_rule);
                }
                continue;
            }

            is_valid = false;
            break;
        }
        good_rule_objects.reserve(rule_objects.size()); // Reserve memory

        for(const auto& rule : rule_set) { // if marked as invalid in the building process
            if(rule.invalid_rule) is_valid = false;
        }

        if(!rule_set.empty() && is_valid) { // don't push empty rulesets
            std::pair<unsigned long, std::vector<Rule>> rule_with_line_number {line_counter, rule_set};
            rule_objects.push_back(rule_with_line_number);
        }
        if(!is_valid) {
            fprintf(stderr, "Invalid Rule [%lu]: \"%s\"\n", line_counter, line.c_str());
            invalid_lines.push_back(std::move(line));
        }
        line_counter++;
    }

    std::cerr << "Completed parsing rules" << std::endl;
    std::vector<std::pair<unsigned long, std::vector<Rule>>> compare_rule_objects;
    if(!compare_rules.empty()) {
        // READ RULES FILE
        std::ifstream compare_rule_file_handle(compare_rules);
        line_counter = 1;
        std::cerr << "Started parsing comparison rules" << std::endl;
        while (std::getline(compare_rule_file_handle, line)) {
            if(line[0] == '#' || (line.size() >= 2 && line[0] == ' ' && line[1] == '#')) {
                line_counter++;
                continue;
            }
            if(hashcat_input) {
                line = convert_from_hashcat(line_counter, line);
            }
            std::string unescaped_line;
            // Unescape
            // Parse escaped hex chars
            for(int i=0; i < line.size(); i++) {
                if (i+3 < line.size() && line[i] == '\\' && line[i + 1] == 'x') {
                    if (isxdigit(line[i + 2]) && isxdigit(line[i + 3])) {
                        int hi = int(line[i + 2]) - 48;
                        if (hi > 10) hi -= 7;
                        if (hi > 15) hi -= 32;

                        int low = int(line[i + 3]) - 48;
                        if (low > 10) low -= 7;
                        if (low > 15) low -= 32;

                        int value = ((int) hi) * 16 + (int)low;
                        unescaped_line += std::string(1, char(value));
                        i+=2;
                    }
                } else {
                    unescaped_line += line[i];
                }
            }

            std::vector<Rule> rule_set;
            std::vector<std::string> raw_rules = split(line, delimiter);
            bool is_valid = true;
            int i = 0;
            for(std::string raw_rule : raw_rules) {
                if(raw_rule.empty()) continue;
                char rule;
                std::string rule_value;
                std::string rule_value_2;
                i++;
                if(i % 100000 == 0) {
                    std::cerr << "Parsed " << i << " rules" << std::endl;
                }

                if(Rule::rule_identify(raw_rule[0]) == 1) {
                    rule = raw_rule[0];
                    Rule single_rule(static_cast<char>(rule), "", "");
                    rule_set.push_back(single_rule);
                    continue;
                }

                if(Rule::rule_identify(raw_rule[0]) == 2 && raw_rule.size() >= 2) {
                    rule = raw_rule[0];
                    rule_value = raw_rule.substr(1, raw_rule.size());
                    Rule single_rule(static_cast<char>(rule), rule_value, "");
                    rule_set.push_back(single_rule);
                    continue;
                }

                if(Rule::rule_identify(raw_rule[0]) == 3 && raw_rule.size() >= 3) {
                    rule = raw_rule[0];
                    rule_value = raw_rule[1];
                    rule_value_2 = raw_rule.substr(2, raw_rule.size());
                    if(count(raw_rule.begin(),raw_rule.end(),'/') >= 2) {
                        replace(raw_rule, "\\/", "\xFF\xFF"); // Fix escaped \/ to /
                        std::vector<std::string> raw_rule_parts = split(raw_rule, '/'); // Fix escaped \/ to /
                        for(auto &raw_rule_part : raw_rule_parts) {
                            replace(raw_rule_part, "\xFF\xFF", "/"); // Fix escaped \/ to /
                        }


                        rule_value = raw_rule_parts[1];
                        rule_value_2 = raw_rule_parts[2];
                        Rule single_rule(static_cast<char>(rule), rule_value, rule_value_2);
                        rule_set.push_back(single_rule);
                    } else {
                        Rule single_rule(static_cast<char>(rule), rule_value, rule_value_2);
                        rule_set.push_back(single_rule);
                    }
                    continue;
                }

                is_valid = false;
                break;
            }
            for(const auto& rule : rule_set) { // if marked as invalid in the building process
                if(rule.invalid_rule) is_valid = false;
            }

            if(!rule_set.empty() && is_valid) { // don't push empty rulesets
                std::pair<unsigned long, std::vector<Rule>> rule_with_line_number {line_counter, rule_set};
                compare_rule_objects.push_back(rule_with_line_number);
            }
            if(!is_valid) {
                if(line[0] != '#') {
                    fprintf(stderr, "Invalid Comparison Rule: \"%s\"\n", line.c_str());
                }
            }
            line_counter++;
        }
        std::cerr << "Completed parsing comparison rules" << std::endl;
    }

    if(optimize_no_op || optimize_same_op || (optimize_similar_op || !compare_rule_objects.empty())) {
        size_t original_rule_objects_size = rule_objects.size();
        std::vector<std::string> test_words;
        if(optimized_words) {
            for (int i = 0x20; i <= 0x7e; i++) {
                test_words.emplace_back(15, char(i));
            }

            std::string all_chars;
            for (int i = 0x20; i <= 0x7e; i++) { // create a string with all possible hex values
                for (int j = 0; j < 15; j++) {
                    all_chars.append(std::string(1, char(i)));
                    all_chars.append(std::string(1, 'a'));
                }
            }
            test_words.push_back(all_chars);
            reverse(all_chars.begin(), all_chars.end());
            test_words.push_back(all_chars);

            for (int i = 3; i < 15; i++) { // create alphanumeric strings of different lengths
                std::string alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
                if (i % 2 == 0) reverse(alphabet.begin(), alphabet.end()); // reverse every other alphabet
                alphabet.erase(0, alphabet.length() - i - 1);
                test_words.push_back(std::move(alphabet));
            }
        } else {
            for (int i = 0x0; i <= 0xff; i++) {
                test_words.emplace_back(37, char(i)); // 37 x the char for 0-9A-Z positional
            }

            std::string all_chars;
            for (int i = 0x0; i <= 0xff; i++) { // create a string with all possible hex values
                for (int j = 0; j < 37; j++) { // 37 x the char for 0-9A-Z positional
                    all_chars.append(std::string(1, char(i)));
                    all_chars.append(std::string(1, 'a'));
                }
            }
            test_words.push_back(all_chars);
            reverse(all_chars.begin(), all_chars.end());
            test_words.push_back(all_chars);

            for (int i = 0; i < 37; i++) { // create alphanumeric strings of different lengths
                std::string alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
                if (i % 2 == 0) reverse(alphabet.begin(), alphabet.end()); // reverse every other alphabet
                alphabet.erase(0, alphabet.length() - i - 1);
                test_words.push_back(std::move(alphabet));
            }
        }

        if(!input_wordlist.empty()) {
            std::cerr << "Overwriting default validation wordlist with custom wordlist. Consider using the --optimized-words flag instead." << std::endl;
            test_words.clear();
            std::ios::sync_with_stdio(false);  // disable syncing with stdio
            std::ifstream fin;
            char stream_buffer[4096];
            fin.rdbuf()->pubsetbuf(stream_buffer, sizeof(stream_buffer)); // set buffer for reading characters
            fin.open(input_wordlist);
            std::string file_line;
            while (std::getline(fin, file_line)) {
                test_words.push_back(std::move(file_line));
            }
        }

        // Pass 1
        // Pass 1
        // Pass 1
        // First pass, intent to see if the rule in itself makes any changes. Removing rules such as $1 ]

        long long progress_counter = 0;
        int barWidth = 70;
        if(optimize_no_op) {
            std::cerr << "Starting no-op" << std::endl;
            time_t start, end;
            time(&start);

            for (size_t t_id = 0; t_id < std::thread::hardware_concurrency(); t_id++) {
                threads.emplace_back(std::thread(&process_stage1_thread, std::ref(test_words)));
            }

            size_t step_counter = (!input_wordlist.empty()) ? 50 : 5000;
            for (std::pair<unsigned long, std::vector<Rule>> &rule_set_pair: rule_objects) {
                // Progress Bar
                progress_counter++;
                while (rule_queue.size() > 10) { // Limit queue size
                    condition_var.notify_one();
                    std::this_thread::sleep_for(std::chrono::milliseconds(20));
                }

                if (progress_counter == 1 || progress_counter % step_counter == 0 || progress_counter == rule_objects.size()) {
                    std::cerr << "\r" << std::flush;
                    std::cerr << "[";
                    double pos = barWidth * (static_cast<double>(progress_counter) / static_cast<double>(rule_objects.size()));
                    for (int i = 0; i < barWidth; ++i) {
                        if (i < pos) std::cerr << "=";
                        else if (i == pos) std::cerr << ">";
                        else std::cerr << " ";
                    }
                    std::cerr << "] " << double(round(static_cast<double>(progress_counter) / static_cast<double>(rule_objects.size()) * 10000) / 100.0) << "% (" << progress_counter << " / " << rule_objects.size() << ")  \r";
                    std::cerr.flush();
                }

                queue_buffer.emplace_back(rule_set_pair);
                if (queue_buffer.size() > 10) {
                    std::unique_lock<std::mutex> lock(lock_obj); // push to queue
                    rule_queue.push(queue_buffer);
                    lock.unlock();

                    queue_buffer.clear();
                    condition_var.notify_one();
                }
            }

            if (!queue_buffer.empty()) {
                std::unique_lock<std::mutex> lock(lock_obj); // push to queue
                rule_queue.push(queue_buffer);
                lock.unlock();

                queue_buffer.clear();
                condition_var.notify_one();
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            is_processing = false;

            while (!rule_queue.empty()) {
                condition_var.notify_all();
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }

            condition_var.notify_all();
            for (auto &thread: threads) {
                condition_var.notify_all();
                if (thread.joinable()) {
                    thread.join();
                }
            }
            threads.clear();
            is_processing = true;


            // Reset rule collection with better rules
            rule_objects = good_rule_objects;
            good_rule_objects.clear();
            good_rule_objects.reserve(rule_objects.size()); // Reserve memory
            time(&end);
            double time_taken = std::ceil(static_cast<double>(end - start) * 100.0) / 100.0;
            std::cerr << std::endl;
            std::cerr << '\r' << std::flush;
            std::cerr << "no-op: " << time_taken << " sec" << std::endl;
        }

        // Pass 2
        // Pass 2
        // Pass 2
        // Goal: PowerSet itself to find the smallest combination of rules that will produce the same result as its original
        if(optimize_same_op) {
            std::cerr << std::endl;
            std::cerr << "Starting same-op" << std::endl;
            time_t start, end;
            time(&start);

            for (size_t t_id = 0; t_id < std::thread::hardware_concurrency(); t_id++) {
                threads.emplace_back(std::thread(&process_stage2_thread, std::ref(test_words)));
            }

            progress_counter = 0;
            size_t step_counter = (!input_wordlist.empty()) ? 5 : 2500;
            for (std::pair<unsigned long, std::vector<Rule>> &rule_set_pair: rule_objects) {
                progress_counter++;
                while (rule_queue.size() > 20) { // Limit queue size
                    condition_var.notify_all();
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
                // Progress Bar
                if (progress_counter % step_counter == 0 || progress_counter == rule_objects.size()) {
                    std::cerr << "\r" << std::flush;
                    std::cerr << "[";
                    double pos = barWidth * (static_cast<double>(progress_counter) / static_cast<double>(rule_objects.size()));
                    for (int i = 0; i < barWidth; ++i) {
                        if (i < pos) std::cerr << "=";
                        else if (i == pos) std::cerr << ">";
                        else std::cerr << " ";
                    }
                    std::cerr << "] " << double(round(static_cast<double>(progress_counter) / static_cast<double>(rule_objects.size()) * 10000) / 100.0)
                              << "% (" << progress_counter << " / " << rule_objects.size() << ") \r";
                    std::cerr.flush();
                }
                if(rule_set_pair.second.size() > 19) {
                    std::cerr << "Skipping. Too many functions [" << rule_set_pair.first << "]: ";
                    for(auto & i : rule_set_pair.second) {
                        i.print(true);
                    }
                    std::cerr << std::endl;
                    continue;
                }

                if (rule_set_pair.second[0].rule == ':') {
                    std::unique_lock<std::mutex> new_lock(result_rule_mutex); // Lock
                    good_rule_objects.emplace_back(rule_set_pair);
                    new_lock.unlock(); // Unlock
                    continue;
                }

                queue_buffer.emplace_back(rule_set_pair);
                if (queue_buffer.size() > 10) {
                    std::unique_lock<std::mutex> lock(lock_obj); // push to queue
                    rule_queue.push(queue_buffer);
                    lock.unlock();

                    queue_buffer.clear();
                    condition_var.notify_one();
                }
            }
            std::cerr << std::endl;
            std::cerr << "Finalizing same-op... please wait, this can take a while" << std::endl;
            // Empty out the queue
            if (!queue_buffer.empty()) {
                std::unique_lock<std::mutex> empty_lock(lock_obj); // push to queue
                rule_queue.push(queue_buffer);
                empty_lock.unlock();
                queue_buffer.clear();
                condition_var.notify_one();
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            is_processing = false;

            while (!rule_queue.empty()) {
                condition_var.notify_all();
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
            condition_var.notify_all();
            for (auto &thread: threads) {
                condition_var.notify_all();
                if (thread.joinable()) {
                    thread.join();
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
            threads.clear();
            is_processing = true;
            // End empty out the queue

            // Reset rule collection with better rules
            rule_objects = good_rule_objects;
            good_rule_objects.clear();
            time(&end);
            double time_taken = std::ceil(static_cast<double>(end - start) * 100.0) / 100.0;
            std::cerr << "same-op: " << time_taken << " sec" << std::endl;
        }

        // Pass 3
        // Pass 3
        // Pass 3
        // Goal: Compare rule one by one against all OTHER rules
        if((optimize_similar_op || !compare_rule_objects.empty()) && !optimize_slow) {
            std::cerr << std::endl;
            std::cerr << "Starting similar-op";
            if(!compare_rule_objects.empty()) {
                std::cerr << " in relation to a comparison file";
            }
            std::cerr << std::endl;
            time_t start, end, absolute_end;
            time(&start);
            long double test_word_size {0};
            for (const std::string &test_word : test_words) {
                test_word_size += sizeof(test_word) * sizeof(test_word[0]);
            }
            test_word_size *= 1.2; // margin

            long double estimated_size = rule_objects.size() * test_word_size * 3; // wordlist size
            if(!compare_rule_objects.empty()) {
                estimated_size += compare_rule_objects.size() * test_word_size * 3;
            }
            // add processed output
            estimated_size *= 2;

            double usage = std::ceil(estimated_size/1000000 * 100.0) / 100.0;
            std::cerr << "Pregenerating data. Estimated Memory usage: " << usage << "MB. \nMemory usage can start off a lot higher than expected, especially if specifying a wordlist." <<  std::endl;

            std::vector<std::vector<std::string>> all_rules_output;
            all_rules_output.reserve(rule_objects.size());
            for (std::pair<unsigned long, std::vector<Rule>> &rule_set_pair: rule_objects) {
                std::vector<std::string> rule_set_output;
                rule_set_output.reserve(test_words.size());

                for (const std::string &test_word: test_words) {
                    std::string new_plain{test_word};
                    for (Rule &rule_item: rule_set_pair.second) {
                        rule_item.process(new_plain);
                    }
                    if (test_word != new_plain && !new_plain.empty()) {
                        rule_set_output.push_back(std::move(new_plain));
                    }
                }
                all_rules_output.push_back(std::move(rule_set_output));
            }

            // render compare rules
            std::vector<std::vector<std::string>> compare_rules_output;
            compare_rules_output.reserve(compare_rule_objects.size());
            for (std::pair<unsigned long, std::vector<Rule>> &rule_set_pair: compare_rule_objects) {
                std::vector<std::string> compare_rule_set_output;
                compare_rule_set_output.reserve(test_words.size());

                for (const std::string &test_word: test_words) {
                    std::string new_plain{test_word};
                    for (Rule &rule_item: rule_set_pair.second) {
                        rule_item.process(new_plain);
                    }
                    if (test_word != new_plain && !new_plain.empty()) {
                        compare_rule_set_output.push_back(std::move(new_plain));
                    }
                }
                compare_rules_output.push_back(std::move(compare_rule_set_output));
            }
            std::cerr << "Completed Pregenerating Data" << std::endl;

            progress_counter = 0;

            if(std::thread::hardware_concurrency() >= 3) {
                for (size_t t_id = 0; t_id < std::thread::hardware_concurrency()-1; t_id++) {
                    threads.emplace_back(std::thread(&process_stage3_thread, std::ref(rule_objects), std::ref(all_rules_output), std::ref(compare_rules_output), std::ref(optimize_similar_op)));
                }
            } else {
                for (size_t t_id = 0; t_id < std::thread::hardware_concurrency(); t_id++) {
                    threads.emplace_back(std::thread(&process_stage3_thread, std::ref(rule_objects), std::ref(all_rules_output), std::ref(compare_rules_output), std::ref(optimize_similar_op)));
                }
            }

            std::vector<long long> buffer;
            size_t step_counter = 250;
            if(!input_wordlist.empty() && optimize_slow) step_counter = 1;
            if(!compare_rule_objects.empty()) step_counter = 1000;
            for (std::pair<unsigned long, std::vector<Rule>> &rule_set_pair: rule_objects) {
                progress_counter++;
                while (rule_queue_stage_3.size() > 100) { // Limit queue size
                    condition_var.notify_one();
                    std::this_thread::sleep_for(std::chrono::milliseconds(20));
                }
                // Progress Bar
                if (progress_counter % step_counter == 0 || progress_counter == rule_objects.size()) {
                    std::cerr << '\r' << std::flush;
                    std::cerr << "[";
                    double pos = barWidth * (static_cast<double>(progress_counter) / static_cast<double>(rule_objects.size()));
                    for (int i = 0; i < barWidth; ++i) {
                        if (i < pos) std::cerr << "=";
                        else if (i == pos) std::cerr << ">";
                        else std::cerr << " ";
                    }
                    std::cerr << "] " << double(round(static_cast<double>(progress_counter) / static_cast<double>(rule_objects.size()) * 10000) / 100.0) << "% (" << progress_counter << " / " << rule_objects.size() << ")  \r";
                    std::cerr.flush();
                }

                if (rule_set_pair.second[0].rule == ':') {
                    std::unique_lock<std::mutex> new_lock(result_rule_mutex); // Lock
                    good_rule_objects.emplace_back(rule_set_pair);
                    new_lock.unlock();
                    continue;
                }

                bool to_skip = false;
                for (const Rule &rule_item: rule_set_pair.second) { // Skip if multi char replace.
                    if (Rule::rule_identify(rule_item.rule) == 3 && rule_item.rule_value_1.size() > 1) to_skip = true;
                }
                if (to_skip) {
                    std::unique_lock<std::mutex> new_lock(result_rule_mutex); // Lock
                    good_rule_objects.emplace_back(rule_set_pair);
                    new_lock.unlock();
                    continue;
                }

                buffer.push_back(progress_counter-1);
                if(buffer.size() > 10) {
                    std::unique_lock<std::mutex> lock(lock_obj); // push to queue
                    rule_queue_stage_3.push(buffer);
                    lock.unlock();
                    condition_var.notify_one();
                    buffer.clear();
                }
            }

            if(!buffer.empty()) {
                std::unique_lock<std::mutex> lock(lock_obj); // push to queue
                rule_queue_stage_3.push(buffer);
                lock.unlock();
                condition_var.notify_one();
                buffer.clear();
            }

            std::cerr << std::endl;
            std::cerr << "\r" << std::flush;
            std::cerr << "Finalizing similar-op" << std::endl;

            // Empty out the queue
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            is_processing = false;
            while (!rule_queue_stage_3.empty()) {
                condition_var.notify_all();
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
            condition_var.notify_all();
            for (auto &thread: threads) {
                condition_var.notify_all();
                if (thread.joinable()) {
                    thread.join();
                }
            }
            threads.clear();
            all_rules_output.clear();
            is_processing = true;
            // End empty out the queue

            rule_objects = good_rule_objects;
            good_rule_objects.clear();
            time(&end);
            time(&absolute_end);
            double time_taken = std::ceil(static_cast<double>(end - start) * 100.0) / 100.0;
            double total_time_taken = std::ceil(static_cast<double>(absolute_end - absolute_start) * 100.0) / 100.0;
            std::cerr << "similar-op: " << time_taken << " sec" << std::endl;
            std::cerr << "Total Time: " << total_time_taken << " sec" << std::endl;
        }


        // Pass 3 Optimize slow
        if((optimize_similar_op || !compare_rule_objects.empty()) && optimize_slow) {
            std::cerr << std::endl;
            std::cerr << "Starting slow similar-op";
            if(!compare_rule_objects.empty()) {
                std::cerr << " in relation to a comparison file";
            }
            std::cerr << std::endl;
            time_t start, end, absolute_end;
            time(&start);
            progress_counter = 0;
            if(std::thread::hardware_concurrency() >= 2) {
                for (size_t t_id = 0; t_id < std::thread::hardware_concurrency()-1; t_id++) {
                    threads.emplace_back(std::thread(&process_stage3_thread_slow, std::ref(rule_objects), std::ref(compare_rule_objects), std::ref(test_words), std::ref(optimize_similar_op)));
                }
            } else {
                threads.emplace_back(std::thread(&process_stage3_thread_slow, std::ref(rule_objects), std::ref(compare_rule_objects), std::ref(test_words), std::ref(optimize_similar_op)));
            }

            std::vector<long long> buffer;
            for (std::pair<unsigned long, std::vector<Rule>> &rule_set_pair: rule_objects) {
                progress_counter++;
                while (rule_queue_stage_3.size() > 500) { // Limit queue size
                    condition_var.notify_one();
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
                // Progress Bar
                if (progress_counter % 10 == 0 || progress_counter == rule_objects.size()) {
                    std::cerr << "\r" << std::flush;
                    std::cerr << "[";
                    double pos = barWidth * (static_cast<double>(progress_counter) / static_cast<double>(rule_objects.size()));
                    for (int i = 0; i < barWidth; ++i) {
                        if (i < pos) std::cerr << "=";
                        else if (i == pos) std::cerr << ">";
                        else std::cerr << " ";
                    }
                    std::cerr << "] " << double(round(static_cast<double>(progress_counter) / static_cast<double>(rule_objects.size()) * 10000) / 100.0) << "% (" << progress_counter << " / " << rule_objects.size() << ")\r";
                    std::cerr.flush();
                }

                if (rule_set_pair.second[0].rule == ':') {
                    std::unique_lock<std::mutex> new_lock(result_rule_mutex); // Lock
                    good_rule_objects.emplace_back(rule_set_pair);
                    new_lock.unlock();
                    continue;
                }

                bool to_skip = false;
                for (const Rule &rule_item: rule_set_pair.second) { // Skip if multi char replace.
                    if (Rule::rule_identify(rule_item.rule) == 3 && rule_item.rule_value_1.size() > 1) to_skip = true;
                }
                if (to_skip) {
                    std::unique_lock<std::mutex> new_lock(result_rule_mutex); // Lock
                    good_rule_objects.emplace_back(rule_set_pair);
                    new_lock.unlock();
                    continue;
                }

                buffer.push_back(progress_counter-1);
                if(buffer.size() > 1) {
                    std::unique_lock<std::mutex> lock(lock_obj); // push to queue
                    rule_queue_stage_3.push(buffer);
                    lock.unlock();
                    condition_var.notify_one();
                    buffer.clear();
                }
            }

            if(!buffer.empty()) {
                std::unique_lock<std::mutex> lock(lock_obj); // push to queue
                rule_queue_stage_3.push(buffer);
                lock.unlock();
                condition_var.notify_one();
                buffer.clear();
            }

            std::cerr << std::endl;
            std::cerr << "\r" << std::flush;
            std::cerr << "Finalizing similar-op" << std::endl;

            // Empty out the queue
            is_processing = false;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            while (!rule_queue_stage_3.empty()) {
                condition_var.notify_all();
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
            condition_var.notify_all();
            for (auto &thread: threads) {
                condition_var.notify_all();
                if (thread.joinable()) {
                    thread.join();
                }
            }
            threads.clear();
            is_processing = true;
            // End empty out the queue

            rule_objects = good_rule_objects;
            good_rule_objects.clear();
            time(&end);
            time(&absolute_end);
            double time_taken = std::ceil(static_cast<double>(end - start) * 100.0) / 100.0;
            double total_time_taken = std::ceil(static_cast<double>(absolute_end - absolute_start) * 100.0) / 100.0;
            std::cerr << "similar-op: " << time_taken << " sec" << std::endl;
            std::cerr << "Total Time: " << total_time_taken << " sec" << std::endl;
        }
        // Write rules to output.
        std::cerr << "Reorganizing rules" << std::endl;
        std::sort(rule_objects.begin(), rule_objects.end(), sort_lineorder_rules);

        std::cerr << std::endl;
        std::cerr << "Completed optimization" << std::endl;
        std::cerr << "Comments (untouched): " << ordered_comments.size() << std::endl;
        std::cerr << "Rules Before: " << original_rule_objects_size + invalid_lines.size() << std::endl;
        std::cerr << "Rules After: " << rule_objects.size() << std::endl;
        std::cerr << "no-op Removed: " << redundant_removed << std::endl;
        std::cerr << "same-op Optimized: " << improvement_counter_level_2 << std::endl;
        if(optimize_similar_op) {
            if(!compare_rule_objects.empty()) {
                std::cerr << "similar-op Removed (self): " << duplicates_removed_level_3 << std::endl;
                std::cerr << "similar-op Removed (compare): " << duplicates_removed_level_3_compare << std::endl;
            } else {
                std::cerr << "similar-op Removed: " << duplicates_removed_level_3 << std::endl;
            }
        } else {
            if(!compare_rule_objects.empty()) {
                std::cerr << "similar-op Removed (compare): " << duplicates_removed_level_3_compare << std::endl;
            } else {
                std::cerr << "similar-op Removed: " << duplicates_removed_level_3 << std::endl;
            }
        }
        std::cerr << "Invalid Removed: " << invalid_lines.size() << std::endl;


        line_counter = 1;
        for(auto& rule_pairs : rule_objects) {
            while(!ordered_comments.empty() && line_counter == ordered_comments[0].first) { // print comments
                std::cout << ordered_comments[0].second << std::endl;
                ordered_comments.erase(ordered_comments.begin());
                line_counter++;
            }
            for(int i = 0; i < rule_pairs.second.size(); i++) {
                rule_pairs.second[i].print();
                if(i != rule_pairs.second.size()-1) {
                    if(hashcat_output) {
                        std::cout << ' '; // hashcat formatting
                    } else {
                        if(!no_delimiter) {
                            std::cout << delimiter; // RuleProcessorY formatting
                        }
                    }
                }
            }
            std::cout << std::endl;
            line_counter++;
        }

//        if(invalid_lines.size() > 1) std::cout << std::endl;
//        for(auto line : invalid_lines) {
//            std::cout << line << std::endl;
//        }
        return 0;
    }

    // Enumerate rules
    std::ifstream fin_test(input_wordlist);
    std::string file_line;
    int carriage_return_test = 0;
    int max_test = 0;
    while (std::getline(fin_test, file_line)) {
        // Remove all carriage return
        if (carriage_return_test > 10) {
            fprintf(stderr, R"(Parse error: wordlist contains carriage returns "\r" aka "^M".)");
            exit(EXIT_FAILURE);
            break;
        }
        if (file_line.find('\r') != std::string::npos) {
            carriage_return_test++;
        }
        max_test++;
        if(max_test > 1000) break;
    }

    std::ios::sync_with_stdio(false);  // disable syncing with stdio
    std::ifstream fin;
    char stream_buffer[4096];
    fin.rdbuf()->pubsetbuf(stream_buffer, sizeof(stream_buffer)); // set buffer for reading characters
    fin.open(input_wordlist);
    while (std::getline(fin, file_line)) {
        for (std::pair<unsigned long, std::vector<Rule>> &rule_pair: rule_objects) {
            if (rule_pair.second[0].rule == ':') {
                for (Rule &rule_item: rule_pair.second) {
                    rule_item.process(file_line);
                }
                if (!file_line.empty()) {
                    std::cout << file_line << '\n';
                }
                continue;
            }
            std::string new_plain{file_line};
            for (Rule &rule_item: rule_pair.second) {
                rule_item.process(new_plain);
            }
            if (file_line != new_plain && !new_plain.empty()) {
                std::cout << new_plain << '\n';
            }
        }
    }
    return 0;
}

