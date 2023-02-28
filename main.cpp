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


static void show_usage() {
    std::cerr << "Usage: RuleProcessorY [option(s)] > results.rule\n"
    << "Options:\n"
    << "\t-h,--help\t\t\tShow this help message\n"
    << "\t-w,--wordlist WORDLIST_FILE\tSpecify the input wordlist path\n"
    << "\t-r,--rules RULE_FILE\t\tSpecify the input rules path\n"
    << "\t--hashcat-input\t\t\tUse hashcat rule format for input rules\n\n"
    << "\t--optimize-no-op\t\tRemove rules that perform no operation \"$1 ]\"\n"
    << "\t--optimize-same-op\t\tRemove rules that perform the same operation \"$1 $1 ]\" => \"$1\"\n"
    << "\t--optimize-similar-op\t\tRemove one of the rules that performs a similar operation \"$1 ^1\" and \"^1 $1\"\n"
    << "\t--optimize-all\t\t\tAll the optimizations!\n"
    << "\t--optimize-compare COMPARE_FILE\tRemove rules from RULE_FILE found in COMPARE_FILE (like similar-op)\n"
    << "\t--optimize-debug\t\tShow the modified rules in STDOUT\n"
    << "\t--optimize-slow\t\t\tDo not use memory to store data\n"
    << "Version: 1.0-limited.14-hashmob\n\n"
    << std::endl;
}

std::vector<std::thread> threads;
std::queue<std::vector<std::vector<Rule>>> rule_queue;
std::queue<std::vector<long long>> rule_queue_stage_3;
std::vector<std::vector<Rule>> queue_buffer;
std::mutex lock_obj;
std::mutex result_rule_mutex;
std::condition_variable condition_var;
std::vector<std::vector<Rule>> good_rule_objects;
std::vector<std::vector<Rule>> bad_rule_objects;
int improvement_counter_level_2 = 0;
int duplicates_removed_level_3_compare = 0;
int duplicates_removed_level_3 = 0;
int redundant_removed = 0;
bool is_processing{true};
bool optimize_debug{false};
std::vector<std::string> invalid_lines;

// Convert from Hashcat to TSV format (for RuleProcessorY)
std::string convert_from_hashcat(std::string rule) {
    // sets of each rule width
    std::set<char> single_wide = { ':', 'l', 'u', 'c', 'C', 't', 'r', 'd', 'f', '{', '}', '[', ']', 'k', 'K', 'q','E' };
    std::set<char> double_wide = { 'T', 'p', 'D', 'Z', 'z', '$', '^', '<', '>', '_', '\'', '!', '/', '@' ,'-', '+', 'y', 'Y', 'L', 'R', '.', ',', 'e' };
    std::set<char> triple_wide = { 's', 'S', 'x', 'O', 'o', 'i', '*', '3' };
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
            formatted_rule += rule.substr(offset, 1) + "\t";
            offset += 1;
        }
            // check if the rule is 2 characters wide
        else if (double_wide.count(baseRule)) {
            // check for hex notation
            if (rule.substr(offset + 1, 2) == "\\x") {
                formatted_rule += rule.substr(offset, 5) + "\t";
                offset += 5;
            }
            else {
                formatted_rule += rule.substr(offset, 2) + "\t";
                offset += 2;
            }
        }
            // check if the rule is 3 characters wide
        else if (triple_wide.count(baseRule)) {
            // check for hex notation
            if (rule.substr(offset + 1, 2) == "\\x") {
                formatted_rule += rule.substr(offset, 6) + "\t";
                offset += 6;
            }
            else {
                formatted_rule += rule.substr(offset, 3) + "\t";
                offset += 3;
            }
        }
            // ignore if the line is a comment
        else if (baseRule == '#')
            offset = 254;
            // error if the baseRule is unknown
        else {
            std::cerr << "Unknown rule format: " << baseRule << ':' << rule << std::endl;
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
        std::vector<std::vector<Rule>> rule_buffer = rule_queue.front();
        rule_queue.pop();
        lock.unlock();

        for(auto rule_set : rule_buffer) {
            bool changes_made = false;
            for (const std::string &test_word: test_words) {
                if (rule_set[0].rule == ':') {
                    changes_made = true;
                    continue;
                }

                std::string new_plain{test_word};
                for (Rule &rule_item: rule_set) {
                    rule_item.process(new_plain);
                }

                if (test_word != new_plain && !new_plain.empty()) {
                    changes_made = true;
                }
            }

            for (Rule &rule_item: rule_set) {
                if (rule_item.rule == 's' && rule_item.rule_value_1 != rule_item.rule_value_2) {
                    changes_made = true;
                }
            }

            if (changes_made) {
                std::unique_lock<std::mutex> new_lock(result_rule_mutex); // Lock
                good_rule_objects.emplace_back(rule_set);
                new_lock.unlock();
            } else {
                if (optimize_debug) {
                    std::unique_lock<std::mutex> new_lock(result_rule_mutex); // Lock
                    std::cout << "Deleted rule:\t";
                    for (int i = 0; i < rule_set.size(); i++) {
                        rule_set[i].print();
                        if (i != rule_set.size() - 1) std::cout << '\t';
                    }
                    std::cout << std::endl;
                    new_lock.unlock();
                }
                redundant_removed++;
            }
        }
    }
}


void process_stage2_thread(const std::vector<std::string>& test_words) {
    while(!rule_queue.empty() || is_processing) {
        std::unique_lock<std::mutex> lock(lock_obj);
        condition_var.wait(lock, [&] {
            return !(rule_queue.empty() && is_processing);
        });
        if(rule_queue.empty()) {
            lock.unlock();
            continue;
        }
        std::vector<std::vector<Rule>> rule_buffer = rule_queue.front();
        rule_queue.pop();
        lock.unlock();

        for(auto rule_set : rule_buffer) {
            // Create PowerSet
            double pow_set_size = pow(2, rule_set.size());
            int counter, j;
            bool found_new = false;

            // Get original rule output to compare against powerset output
            std::vector<std::string> original_rule_output;
            for (const std::string &test_word: test_words) {
                std::string new_plain{test_word};
                for (Rule &rule_item: rule_set) {
                    rule_item.process(new_plain);
                }

                if (test_word != new_plain && !new_plain.empty()) {
                    original_rule_output.push_back(std::move(new_plain));
                }
            }
            // End fetching original rule output

            for (counter = 0; counter < pow_set_size; counter++) {
                std::vector<Rule> rule_power_set_item;
                for (j = 0; j < rule_set.size(); j++) {
                    if (counter & (1 << j))
                        rule_power_set_item.emplace_back(rule_set[j]);
                }
                if(rule_power_set_item.size() > 1 && rule_power_set_item.size() < rule_set.size()) {
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
                        for (const Rule &rule_item: rule_set) {
                            if (Rule::rule_identify(rule_item.rule) == 3 && rule_item.rule_value_1.size() > 1) {
                                modify = false;
                            }
                        }

                        if (modify) {
                            found_new = true;
                            std::unique_lock<std::mutex> new_lock(result_rule_mutex); // Lock
                            if(optimize_debug) {
                                std::cout << "Before:\t";
                                for (Rule rule: rule_set) {
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
                            // Add better rule
                            good_rule_objects.push_back(std::move(rule_power_set_item));
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
                good_rule_objects.push_back(std::move(rule_set));
                new_lock.unlock(); // Unlock
            }
            // end of buffer
        }
        //finalize
    }
}

void process_stage3_thread(std::vector<std::vector<Rule>>& all_rules, const std::vector<std::vector<std::string>>& all_rules_output, std::vector<std::vector<Rule>>& all_compare_rules, const std::vector<std::vector<std::string>>& all_compare_rules_output) {
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
            std::vector<Rule> rule_set = all_rules[rule_iterator];
            if(all_rules.size() < 2) { // Skip if too small
                std::unique_lock<std::mutex> new_lock(result_rule_mutex); // Lock
                good_rule_objects.emplace_back(rule_set);
                new_lock.unlock();
                continue;
            }

            // Get rule set output from every other rule set
            bool matches_none = true;
            if(!all_compare_rules.empty()) { // if comparing to another rule-set
                for (size_t i = 0; i <= all_compare_rules.size(); i++) {
                    std::vector<Rule> &rule_set_comparison = all_compare_rules[i];
                    // Compare output from ruleset with comparison ruleset and if matches, do not save rule (i.e. delete it)
                    if (all_rules_output[rule_iterator] == all_compare_rules_output[i]) {
                        // if good_rule_objects contains rule_set -> skip
                        matches_none = false;
                        duplicates_removed_level_3_compare++;

                        std::unique_lock<std::mutex> new_lock(result_rule_mutex); // Lock
                        if(optimize_debug) {
                            std::cout << std::endl;
                            std::cout << "Deleted:\t";
                            for(int j = 0; j < all_rules[i].size(); j++) {
                                all_rules[i][j].print();
                                if(j != all_rules[i].size()-1) std::cout << '\t';
                            }
                            std::cout << std::endl;
                        }
                        bad_rule_objects.emplace_back(rule_set);
                        new_lock.unlock();
                    }
                }
            }

            // Comparing to itself
            for (size_t i = 0; i < all_rules.size(); i++) {
                std::vector<Rule> &rule_set_comparison = all_rules[i];
                // Compare output from ruleset with comparison ruleset
                if (all_rules_output[rule_iterator] == all_rules_output[i] && i != rule_iterator) {
                    // if good_rule_objects contains rule_set -> skip
                    matches_none = false;
                    bool rule_set_is_good = false;
                    std::unique_lock<std::mutex> good_lock(result_rule_mutex);
                    if (std::find(good_rule_objects.begin(), good_rule_objects.end(), rule_set) != good_rule_objects.end()) { // if original rule is good, do nothing, but do not add rule_set to good or bad
                        rule_set_is_good = true;
                    }
                    if (std::find(bad_rule_objects.begin(), bad_rule_objects.end(), rule_set) != bad_rule_objects.end()) { // if original rule is bad
                        good_lock.unlock();
                        continue;
                    }
                    if (std::find(good_rule_objects.begin(), good_rule_objects.end(), rule_set_comparison) != good_rule_objects.end()) { // if comparison is good -> skip
                        good_lock.unlock();
                        continue;
                    }
                    if (std::find(bad_rule_objects.begin(), bad_rule_objects.end(), rule_set_comparison) != bad_rule_objects.end()) { // if comparison is bad -> skip
                        good_lock.unlock();
                        continue;
                    }
                    duplicates_removed_level_3++;

                    // save smaller or equal size.
                    if (rule_set.size() <= rule_set_comparison.size()) {
                        if(optimize_debug) {
                            if(!rule_set_is_good) {
                                std::cout << "Kept:\t";
                            } else {
                                std::cout << "Already Exists:\t";
                            }
                            for (int j = 0; j < rule_set.size(); j++) {
                                rule_set[j].print();
                                if (j != rule_set.size() - 1) std::cout << '\t';
                            }
                            std::cout << std::endl;
                            std::cout << "Deleted:\t";
                            for(int j = 0; j < all_rules[i].size(); j++) {
                                all_rules[i][j].print();
                                if(j != all_rules[i].size()-1) std::cout << '\t';
                            }
                            std::cout << std::endl;
                        }
                        if(!rule_set_is_good) { // if the rule_set is not already part of the good_rules, add it
                            good_rule_objects.emplace_back(rule_set);
                        }
                        bad_rule_objects.emplace_back(rule_set_comparison);
                        good_lock.unlock();
                        continue;
                    }

                    if(optimize_debug) {
                        if(rule_set_is_good) { // rule set is already good
                            std::cout << "Already Kept:\t";
                            for (int j = 0; j < rule_set.size(); j++) {
                                rule_set[j].print();
                                if (j != rule_set.size() - 1) std::cout << '\t';
                            }
                            std::cout << std::endl;
                            std::cout << "Deleted:\t";
                            for (int j = 0; j < rule_set_comparison.size(); j++) {
                                rule_set_comparison[j].print();
                                if (j != rule_set_comparison.size() - 1) std::cout << '\t';
                            }
                            std::cout << std::endl;
                        } else {
                            std::cout << "Kept:\t";
                            for (int j = 0; j < rule_set_comparison.size(); j++) {
                                rule_set_comparison[j].print();
                                if (j != rule_set_comparison.size() - 1) std::cout << '\t';
                            }
                            std::cout << std::endl;
                            std::cout << "Deleted:\t";
                            for (int j = 0; j < rule_set.size(); j++) {
                                rule_set[j].print();
                                if (j != rule_set.size() - 1) std::cout << '\t';
                            }
                            std::cout << std::endl;
                        }

                    }

                    if(rule_set_is_good) { // rule set is already good
                        bad_rule_objects.emplace_back(rule_set_comparison);
                    } else { // rule set is not good
                        good_rule_objects.emplace_back(rule_set_comparison);
                        bad_rule_objects.emplace_back(rule_set);
                    }
                    good_lock.unlock();
                    continue;
                }
            }

            // default behaviour if nothing matches and it's unique
            if (matches_none) {
                std::unique_lock<std::mutex> lock_match(result_rule_mutex); // Lock
                if(optimize_debug) {
                    std::cout << "Kept new:\t";
                    for (int j = 0; j < rule_set.size(); j++) {
                        rule_set[j].print();
                        if (j != rule_set.size() - 1) std::cout << '\t';
                    }
                    std::cout << std::endl;
                }
                good_rule_objects.emplace_back(rule_set);
                lock_match.unlock();
            }
        }
    }
}


void process_stage3_thread_slow(std::vector<std::vector<Rule>>& all_rules, std::vector<std::vector<Rule>>& all_compare_rules, const std::vector<std::string>& test_words) {
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
            std::vector<Rule> rule_set = all_rules[rule_iterator];
            if(all_rules.size() < 2) { // Skip if too small
                std::unique_lock<std::mutex> new_lock(result_rule_mutex); // Lock
                good_rule_objects.emplace_back(rule_set);
                new_lock.unlock();
                continue;
            }

            std::vector<std::string> rule_set_output;
            rule_set_output.reserve(test_words.size());

            for (const std::string &test_word: test_words) {
                std::string new_plain{test_word};
                for (Rule &rule_item: rule_set) {
                    rule_item.process(new_plain);
                }
                if (test_word != new_plain && !new_plain.empty()) {
                    rule_set_output.push_back(std::move(new_plain));
                }
            }

            // Get rule set output from every other rule set
            bool matches_none = true;
            if(!all_compare_rules.empty()) { // if comparing to another rule-set
                for (size_t i = 0; i <= all_compare_rules.size(); i++) {
                    std::vector<Rule> &rule_set_comparison = all_compare_rules[i];

                    std::vector<std::string> compare_rule_set_output;
                    compare_rule_set_output.reserve(test_words.size());

                    for (const std::string &test_word: test_words) {
                        std::string new_plain{test_word};
                        for (Rule &rule_item: rule_set_comparison) {
                            rule_item.process(new_plain);
                        }
                        if (test_word != new_plain && !new_plain.empty()) {
                            compare_rule_set_output.push_back(std::move(new_plain));
                        }
                    }
                    // Compare output from ruleset with comparison ruleset and if matches, do not save rule (i.e. delete it
                    if (rule_set_output == compare_rule_set_output) {
                        // if good_rule_objects contains rule_set -> skip
                        matches_none = false;
                        duplicates_removed_level_3_compare++;

                        std::unique_lock<std::mutex> new_lock(result_rule_mutex); // Lock
                        if(optimize_debug) {
                            std::cout << std::endl;
                            std::cout << "Deleted:\t";
                            for(int j = 0; j < all_rules[i].size(); j++) {
                                all_rules[i][j].print();
                                if(j != all_rules[i].size()-1) std::cout << '\t';
                            }
                            std::cout << std::endl;
                        }
                        bad_rule_objects.emplace_back(rule_set);
                        new_lock.unlock();
                    }
                }
            }

            // Comparing to itself
            for (size_t i = 0; i < all_rules.size(); i++) {
                std::vector<Rule> &rule_set_comparison = all_rules[i];

                std::vector<std::string> compare_rule_set_output;
                compare_rule_set_output.reserve(test_words.size());

                for (const std::string &test_word: test_words) {
                    std::string new_plain{test_word};
                    for (Rule &rule_item: rule_set_comparison) {
                        rule_item.process(new_plain);
                    }
                    if (test_word != new_plain && !new_plain.empty()) {
                        compare_rule_set_output.push_back(std::move(new_plain));
                    }
                }
                // Compare output from ruleset with comparison ruleset
                if (rule_set_output == compare_rule_set_output && i != rule_iterator) {
                    // if good_rule_objects contains rule_set -> skip
                    matches_none = false;
                    bool rule_set_is_good = false;
                    std::unique_lock<std::mutex> good_lock(result_rule_mutex);
                    if (std::find(good_rule_objects.begin(), good_rule_objects.end(), rule_set) != good_rule_objects.end()) { // if original rule is good, do nothing, but do not add rule_set to good or bad
                        rule_set_is_good = true;
                    }
                    if (std::find(bad_rule_objects.begin(), bad_rule_objects.end(), rule_set) != bad_rule_objects.end()) { // if original rule is bad
                        good_lock.unlock();
                        continue;
                    }
                    if (std::find(good_rule_objects.begin(), good_rule_objects.end(), rule_set_comparison) != good_rule_objects.end()) { // if comparison is good -> skip
                        good_lock.unlock();
                        continue;
                    }
                    if (std::find(bad_rule_objects.begin(), bad_rule_objects.end(), rule_set_comparison) != bad_rule_objects.end()) { // if comparison is bad -> skip
                        good_lock.unlock();
                        continue;
                    }
                    duplicates_removed_level_3++;

                    // save smaller or equal size.
                    if (rule_set.size() <= rule_set_comparison.size()) {
                        if(optimize_debug) {
                            if(!rule_set_is_good) {
                                std::cout << "Kept:\t";
                            } else {
                                std::cout << "Already Exists:\t";
                            }
                            for (int j = 0; j < rule_set.size(); j++) {
                                rule_set[j].print();
                                if (j != rule_set.size() - 1) std::cout << '\t';
                            }
                            std::cout << std::endl;
                            std::cout << "Deleted:\t";
                            for(int j = 0; j < all_rules[i].size(); j++) {
                                all_rules[i][j].print();
                                if(j != all_rules[i].size()-1) std::cout << '\t';
                            }
                            std::cout << std::endl;
                        }
                        if(!rule_set_is_good) { // if the rule_set is not already part of the good_rules, add it
                            good_rule_objects.emplace_back(rule_set);
                        }
                        bad_rule_objects.emplace_back(rule_set_comparison);
                        good_lock.unlock();
                        continue;
                    }

                    if(optimize_debug) {
                        if(rule_set_is_good) { // rule set is already good
                            std::cout << "Already Kept:\t";
                            for (int j = 0; j < rule_set.size(); j++) {
                                rule_set[j].print();
                                if (j != rule_set.size() - 1) std::cout << '\t';
                            }
                            std::cout << std::endl;
                            std::cout << "Deleted:\t";
                            for (int j = 0; j < rule_set_comparison.size(); j++) {
                                rule_set_comparison[j].print();
                                if (j != rule_set_comparison.size() - 1) std::cout << '\t';
                            }
                            std::cout << std::endl;
                        } else {
                            std::cout << "Kept:\t";
                            for (int j = 0; j < rule_set_comparison.size(); j++) {
                                rule_set_comparison[j].print();
                                if (j != rule_set_comparison.size() - 1) std::cout << '\t';
                            }
                            std::cout << std::endl;
                            std::cout << "Deleted:\t";
                            for (int j = 0; j < rule_set.size(); j++) {
                                rule_set[j].print();
                                if (j != rule_set.size() - 1) std::cout << '\t';
                            }
                            std::cout << std::endl;
                        }

                    }

                    if(rule_set_is_good) { // rule set is already good
                        bad_rule_objects.emplace_back(rule_set_comparison);
                    } else { // rule set is not good
                        good_rule_objects.emplace_back(rule_set_comparison);
                        bad_rule_objects.emplace_back(rule_set);
                    }
                    good_lock.unlock();
                    continue;
                }
            }

            // default behaviour if nothing matches and it's unique
            if (matches_none) {
                std::unique_lock<std::mutex> new_lock(result_rule_mutex); // Lock
                if(optimize_debug) {
                    std::cout << "Kept new:\t";
                    for (int j = 0; j < rule_set.size(); j++) {
                        rule_set[j].print();
                        if (j != rule_set.size() - 1) std::cout << '\t';
                    }
                    std::cout << std::endl;
                }
                good_rule_objects.emplace_back(rule_set);
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
    bool help{false};
    bool optimize_slow{false};
    bool optimize_no_op{false};
    bool optimize_same_op{false};
    bool optimize_similar_op{false};
    bool hashcat_input{false};
    std::ios_base::sync_with_stdio(false); // unsync the IO of C and C++
    time_t absolute_start;
    time(&absolute_start);

    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--wordlist" || std::string(argv[i]) == "-w") {
            if (i + 1 < argc && argv[i+1][0] != '-' && strlen(argv[i+1]) > 1 ) {
                input_wordlist = argv[i+1];
            } else {
                std::cerr << argv[i] << " option requires an argument." << std::endl;
                return -1;
            }
        }
        if (std::string(argv[i]) == "--rule" || std::string(argv[i]) == "-r") {
            if (i + 1 < argc && argv[i+1][0] != '-' && strlen(argv[i+1]) > 1) {
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
        if (std::string(argv[i]) == "--optimize-similar-op") { // stage 3
            optimize_similar_op = true;
        }
        if (std::string(argv[i]) == "--optimize-all") {
            optimize_no_op = true; // stage 1
            optimize_same_op = true; //stage 2
            optimize_similar_op = true; //stage 3
        }

        if (std::string(argv[i]) == "--optimize-compare") {
            if (i + 1 < argc && argv[i+1][0] != '-' && strlen(argv[i+1]) > 1) {
                compare_rules = argv[i+1];
                std::cerr << "--optimize-compare has automatically enabled --optimize-similar-op." << std::endl;
            } else {
                std::cerr << argv[i] << " option requires an argument." << std::endl;
                return -1;
            }
        }
        // END OPTIMIZE FLAGS
        if (std::string(argv[i]) == "--optimize-debug") {
            optimize_debug = true;
        }
        if (std::string(argv[i]) == "--optimize-slow") {
            optimize_slow = true;
            std::cerr << "You are running slow mode, this can take forever and a day - be warned." << std::endl << "Computation time is exponentially larger in return for less RAM usage and should only be used as a last resort." <<  std::endl;
        }
    }

    if(help) {
        show_usage();
        return 1;
    }

    if(!(optimize_no_op || optimize_same_op || optimize_similar_op) && (input_wordlist.empty() || input_rules.empty())) {
        show_usage();
        return 1;
    }

    std::vector<std::vector<Rule>> rule_objects;
    if(!(optimize_no_op || optimize_same_op || optimize_similar_op) && !file_exists(input_wordlist)) {
        fprintf(stderr, "Wordlist file error: \"%s\" does not exist.\n", input_wordlist.c_str());
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

    // READ RULES FILE
    std::string line;
    std::ifstream rule_file_handle(input_rules);
    std::vector<std::vector<Rule>> full_rule_set;
    int line_counter = 1;
    while (std::getline(rule_file_handle, line)) {
        if(hashcat_input) {
            line = convert_from_hashcat(line);
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
        std::vector<std::string> raw_rules = split(line, '\t');
        bool is_valid = true;
        for(std::string raw_rule : raw_rules) {
            if(raw_rule.empty()) continue;
            char rule;
            std::string rule_value;
            std::string rule_value_2;

            if(Rule::rule_identify(raw_rule[0]) == 1) {
                rule = raw_rule[0];
                Rule single_rule(static_cast<char>(rule), "", "");
                rule_set.push_back(single_rule);
                line_counter++;
                continue;
            }

            if(Rule::rule_identify(raw_rule[0]) == 2 && raw_rule.size() >= 2) {
                rule = raw_rule[0];
                rule_value = raw_rule.substr(1, raw_rule.size());
                Rule single_rule(static_cast<char>(rule), rule_value, "");
                rule_set.push_back(single_rule);
                line_counter++;
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
                line_counter++;
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
            rule_objects.push_back(rule_set);
        }
        if(!is_valid) {
            fprintf(stderr, "Invalid Rule: \"%s\"\n", line.c_str());
            invalid_lines.push_back(std::move(line));
        }
    }
    std::cerr << "Completed parsing rules" << std::endl;

    std::vector<std::vector<Rule>> compare_rule_objects;
    if((optimize_no_op || optimize_same_op || optimize_similar_op) && !compare_rules.empty()) {
        // READ RULES FILE
        std::ifstream compare_rule_file_handle(compare_rules);
        line_counter = 1;
        while (std::getline(compare_rule_file_handle, line)) {
            std::vector<Rule> rule_set;
            std::vector<std::string> raw_rules = split(line, '\t');
            bool is_valid = true;
            for(std::string raw_rule : raw_rules) {
                if(raw_rule.empty()) continue;
                char rule;
                std::string rule_value;
                std::string rule_value_2;

                if(Rule::rule_identify(raw_rule[0]) == 1) {
                    rule = raw_rule[0];
                    Rule single_rule(static_cast<char>(rule), "", "");
                    rule_set.push_back(single_rule);
                    line_counter++;
                    continue;
                }

                if(Rule::rule_identify(raw_rule[0]) == 2 && raw_rule.size() >= 2) {
                    rule = raw_rule[0];
                    rule_value = raw_rule.substr(1, raw_rule.size());
                    Rule single_rule(static_cast<char>(rule), rule_value, "");
                    rule_set.push_back(single_rule);
                    line_counter++;
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
                    line_counter++;
                    continue;
                }

                is_valid = false;
                break;
            }
            for(const auto& rule : rule_set) { // if marked as invalid in the building process
                if(rule.invalid_rule) is_valid = false;
            }

            if(!rule_set.empty() && is_valid) { // don't push empty rulesets
                compare_rule_objects.push_back(rule_set);
            }
            if(!is_valid) {
                fprintf(stderr, "Invalid Comparison Rule: \"%s\"\n", line.c_str());
            }
        }
        std::cerr << "Completed parsing comparison rules" << std::endl;
    }

    if(optimize_no_op || optimize_same_op || optimize_similar_op) {
        std::vector<std::vector<Rule>> original_rule_objects = rule_objects;
        std::vector<std::string> test_words;
        test_words.reserve(300);
        for(int i = 0x0 ; i <= 0xff ; i++) {
            test_words.emplace_back(std::string(37, char(i)));
        }

        std::string all_chars;
        for(int i = 0x0 ; i <= 0xff ; i++) { // create a string with all possible hex values
            all_chars.append(std::string(1, char(i)));
            all_chars.append(std::string(1, 'a'));
        }
        test_words.push_back(all_chars);
        reverse(all_chars.begin(), all_chars.end());
        test_words.push_back(all_chars);

        for(int i = 0; i < 37; i++) { // create alphanumeric strings of different lengths
            std::string alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
            if(i % 2 == 0) reverse(alphabet.begin(), alphabet.end()); // reverse every other alphabet
            alphabet.erase(0, alphabet.length()-i-1);
            test_words.push_back(std::move(alphabet));
        }

        if(!input_wordlist.empty()) {
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

            size_t step_counter = (!input_wordlist.empty()) ? 5 : 5000;
            for (std::vector<Rule> &rule_set: rule_objects) {
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
                    std::cerr << "] " << double(round(static_cast<double>(progress_counter) / static_cast<double>(rule_objects.size()) * 10000) / 100.0) << "% (" << progress_counter << " / " << rule_objects.size() << ")\r";
                    std::cerr.flush();
                }

                queue_buffer.emplace_back(rule_set);
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
            is_processing = false;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));

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
            std::cerr << "\33[2K\r" << std::flush;
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
            for (std::vector<Rule> &rule_set: rule_objects) {
                progress_counter++;
                while (rule_queue.size() > 10) { // Limit queue size
                    condition_var.notify_one();
                    std::this_thread::sleep_for(std::chrono::milliseconds(20));
                }
                // Progress Bar
                if (progress_counter % step_counter == 0 || progress_counter == rule_objects.size()) {
                    std::cerr << "\r" << std::flush;
                    std::cerr << "[";
                    double pos = barWidth *
                                 (static_cast<double>(progress_counter) / static_cast<double>(rule_objects.size()));
                    for (int i = 0; i < barWidth; ++i) {
                        if (i < pos) std::cerr << "=";
                        else if (i == pos) std::cerr << ">";
                        else std::cerr << " ";
                    }
                    std::cerr << "] " << double(
                            round(static_cast<double>(progress_counter) / static_cast<double>(rule_objects.size()) *
                                  10000) / 100.0) << "% (" << progress_counter << " / " << rule_objects.size() << ")\r";
                    std::cerr.flush();
                }

                if (rule_set[0].rule == ':') {
                    std::unique_lock<std::mutex> new_lock(result_rule_mutex); // Lock
                    good_rule_objects.emplace_back(rule_set);
                    new_lock.unlock(); // Unlock
                    continue;
                }

                queue_buffer.emplace_back(rule_set);
                if (queue_buffer.size() > 5) {
                    std::unique_lock<std::mutex> lock(lock_obj); // push to queue
                    rule_queue.push(queue_buffer);
                    lock.unlock();

                    queue_buffer.clear();
                    condition_var.notify_one();
                }
            }
            std::cerr << std::endl;
            std::cerr << "\33[2K\r" << std::flush;
            std::cerr << "Finalizing same-op... please wait, this can take a while" << std::endl;
            // Empty out the queue
            if (!queue_buffer.empty()) {
                std::unique_lock<std::mutex> empty_lock(lock_obj); // push to queue
                rule_queue.push(queue_buffer);
                empty_lock.unlock();
                queue_buffer.clear();
                condition_var.notify_one();
            }
            is_processing = false;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));

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
        if(optimize_similar_op && !optimize_slow) {
            std::cerr << std::endl;
            std::cerr << "Starting similar-op";
            if(!compare_rule_objects.empty()) {
                std::cerr << " in relation to a comparison file";
            }
            std::cerr << std::endl;
            time_t start, end, absolute_end;
            time(&start);
            long long estimated_size = rule_objects.size() * test_words.size() * sizeof(test_words[0]) + sizeof(std::vector<std::string>) * rule_objects.size();
            if(!compare_rule_objects.empty()) {
                estimated_size += compare_rule_objects.size() * test_words.size() * sizeof(test_words[0]) + sizeof(std::vector<std::string>) * compare_rule_objects.size();
            }
            double usage = std::ceil(estimated_size/1000000 * 100.0) / 100.0;
            std::cerr << "Pregenerating data. Estimated Memory usage: " << usage << "MB. \nMemory usage starts off a few GB higher, especially if specifying a wordlist." <<  std::endl;

            std::vector<std::vector<std::string>> all_rules_output;
            all_rules_output.reserve(rule_objects.size());
            for (std::vector<Rule> &rule_set: rule_objects) {
                std::vector<std::string> rule_set_output;
                rule_set_output.reserve(test_words.size());

                for (const std::string &test_word: test_words) {
                    std::string new_plain{test_word};
                    for (Rule &rule_item: rule_set) {
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
            for (std::vector<Rule> &rule_set: compare_rule_objects) {
                std::vector<std::string> compare_rule_set_output;
                compare_rule_set_output.reserve(test_words.size());

                for (const std::string &test_word: test_words) {
                    std::string new_plain{test_word};
                    for (Rule &rule_item: rule_set) {
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

            for (size_t t_id = 0; t_id < std::thread::hardware_concurrency(); t_id++) {
                threads.emplace_back(std::thread(&process_stage3_thread, std::ref(rule_objects), std::ref(all_rules_output), std::ref(compare_rule_objects), std::ref(compare_rules_output)));
            }

            std::vector<long long> buffer;
            size_t step_counter = (!input_wordlist.empty() && optimize_slow) ? 1 : 250;
            for (std::vector<Rule> &rule_set: rule_objects) {
                progress_counter++;
                while (rule_queue_stage_3.size() > 100) { // Limit queue size
                    condition_var.notify_one();
                    std::this_thread::sleep_for(std::chrono::milliseconds(20));
                }
                // Progress Bar
                if (progress_counter % step_counter == 0 || progress_counter == rule_objects.size()) {
                    std::cerr << "\33[2K\r" << std::flush;
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

                if (rule_set[0].rule == ':') {
                    std::unique_lock<std::mutex> new_lock(result_rule_mutex); // Lock
                    good_rule_objects.emplace_back(rule_set);
                    new_lock.unlock();
                    continue;
                }

                bool to_skip = false;
                for (const Rule &rule_item: rule_set) { // Skip if multi char replace.
                    if (Rule::rule_identify(rule_item.rule) == 3 && rule_item.rule_value_1.size() > 1) to_skip = true;
                }
                if (to_skip) {
                    std::unique_lock<std::mutex> new_lock(result_rule_mutex); // Lock
                    good_rule_objects.emplace_back(rule_set);
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
        if(optimize_similar_op && optimize_slow) {
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
                for (size_t t_id = 0; t_id < std::thread::hardware_concurrency()-2; t_id++) {
                    threads.emplace_back(std::thread(&process_stage3_thread_slow, std::ref(rule_objects), std::ref(compare_rule_objects), std::ref(test_words)));
                }
            } else {
                threads.emplace_back(std::thread(&process_stage3_thread_slow, std::ref(rule_objects), std::ref(compare_rule_objects), std::ref(test_words)));
            }

            std::vector<long long> buffer;
            for (std::vector<Rule> &rule_set: rule_objects) {
                progress_counter++;
                while (rule_queue_stage_3.size() > 100) { // Limit queue size
                    condition_var.notify_one();
                    std::this_thread::sleep_for(std::chrono::milliseconds(20));
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

                if (rule_set[0].rule == ':') {
                    std::unique_lock<std::mutex> new_lock(result_rule_mutex); // Lock
                    good_rule_objects.emplace_back(rule_set);
                    new_lock.unlock();
                    continue;
                }

                bool to_skip = false;
                for (const Rule &rule_item: rule_set) { // Skip if multi char replace.
                    if (Rule::rule_identify(rule_item.rule) == 3 && rule_item.rule_value_1.size() > 1) to_skip = true;
                }
                if (to_skip) {
                    std::unique_lock<std::mutex> new_lock(result_rule_mutex); // Lock
                    good_rule_objects.emplace_back(rule_set);
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

        std::cerr << std::endl;
        std::cerr << "Completed optimization" << std::endl;
        std::cerr << "Before: " << original_rule_objects.size()+invalid_lines.size() << std::endl;
        std::cerr << "After: " << rule_objects.size() << std::endl;
        std::cerr << "no-op Removed: " << redundant_removed << std::endl;
        std::cerr << "same-op Optimized: " << improvement_counter_level_2 << std::endl;
        if(compare_rule_objects.empty()) {
            std::cerr << "similar-op Removed: " << duplicates_removed_level_3 << std::endl;
        } else {
            std::cerr << "similar-op Removed (self): " << duplicates_removed_level_3 << std::endl;
            std::cerr << "similar-op Removed (compare): " << duplicates_removed_level_3_compare << std::endl;
        }
        std::cerr << "Invalid Removed: " << invalid_lines.size() << std::endl;

        for(auto rules : rule_objects) {
            for(int i = 0; i < rules.size(); i++) {
                rules[i].print();
                if(i != rules.size()-1) std::cout << '\t';
            }
            std::cout << std::endl;
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
        for (std::vector<Rule> &rule_set: rule_objects) {
            if (rule_set[0].rule == ':') {
                for (Rule &rule_item: rule_set) {
                    rule_item.process(file_line);
                }
                if (!file_line.empty()) {
                    std::cout << file_line << '\n';
                }
                continue;
            }
            std::string new_plain{file_line};
            for (Rule &rule_item: rule_set) {
                rule_item.process(new_plain);
            }
            if (file_line != new_plain && !new_plain.empty()) {
                std::cout << new_plain << '\n';
            }
        }
    }
    return 0;
}
