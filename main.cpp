#include <cstdio>
#include <string>
#include <vector>
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <boost/program_options.hpp>
#include "json.hpp" // https://github.com/nlohmann/json
#include "rule.h"


// A more versatile rule processor by Vavaldi // 0x69be027c97
// Get started with:
// <filename> -h
// <filename> --help

using namespace boost::program_options;
using json = nlohmann::json;


inline bool file_exists (const std::string& file_name) {
    std::ifstream infile(file_name);
    return infile.good();
}

int main(int argc, const char *argv[])
{
    try {
        options_description desc{"Vavaldi's Rule Processor Options"};
        desc.add_options()
        ("help,h", "Help screen")
        ("version,v", "Display version")
        ("wordlist,w", value<std::string>(), "Wordlist of plains.")
        ("rules,r", value<std::string>(), "JSON Style rules");

        variables_map vm;
        store(parse_command_line(argc, argv, desc), vm);
        notify(vm);

        std::vector<std::vector<Rule>> rule_objects;

        if (vm.count("version")) {
            fprintf(stdout, "Version: 0.5.1\n");
        } else if (vm.count("wordlist") && vm.count("rules")) {
            // Try parsing rules from json format file.
            std::string input_file = vm["wordlist"].as<std::string>();
            std::string input_rules = vm["rules"].as<std::string>();
            json parsed_rules;
            if(!file_exists(input_file)) {
                fprintf(stderr, "Wordlist file error: \"%s\" does not exist.\n", input_rules.c_str());
                exit(EXIT_FAILURE);
            }
            if(!file_exists(input_rules)) {
                fprintf(stderr, "Rule file error: \"%s\" does not exist.\n", input_rules.c_str());
                exit(EXIT_FAILURE);
            }

            try {
                std::ifstream i(input_rules);
                i >> parsed_rules;
            } catch (const nlohmann::detail::exception &test) {
                std::cerr << test.what() << '\n';
                exit(EXIT_FAILURE);
            }

            fprintf(stderr, "There are %lu rules.\n", parsed_rules.size());
            int rule_set_counter{ 0 };

            // Loop through all rules:
            for (auto &single_rule_set : parsed_rules) {
                rule_set_counter++;
                std::vector<Rule> rule_set;
                // Simple ruleset handler (unary and binary)
                if(single_rule_set.is_string()) {
                    char rule;
                    std::string rule_value;
                    std::string rule_value_2;
                    if(single_rule_set.get<std::string>().size() == 1) {
                        rule = single_rule_set.get<std::string>()[0];
                        rule_value = single_rule_set.get<std::string>().substr(1, single_rule_set.size());
                        Rule single_rule(static_cast<char>(rule), rule_value, "");
                        rule_set.push_back(single_rule);
                    }
                    else if(single_rule_set.get<std::string>().size() == 2) {
                        rule = single_rule_set.get<std::string>()[0];
                        rule_value = single_rule_set.get<std::string>()[1];
                        Rule single_rule(static_cast<char>(rule), rule_value, "");
                        rule_set.push_back(single_rule);
                    }
                    else if(single_rule_set.get<std::string>().size() == 3) {
                        rule = single_rule_set.get<std::string>()[0];
                        rule_value = single_rule_set.get<std::string>()[1];
                        rule_value_2 = single_rule_set.get<std::string>()[2];
                        Rule single_rule(static_cast<char>(rule), rule_value, rule_value_2);
                        rule_set.push_back(single_rule);
                    } else {
                        fprintf(stderr, "Parse error: object %d is too long. 1-3 characters expected, received: %lu\n", rule_set_counter, single_rule_set.size());
                        exit(EXIT_FAILURE);
                    }
                    rule_objects.push_back(rule_set);
                    continue;
                }

                if (single_rule_set.empty()) {
                    fprintf(stderr, "Parse warning: object %d found without rules.\n", rule_set_counter);
                }

                int rule_counter{ 0 };

                // Loop through the parts of a rule such as: [si4, sa@, i0_]
                // for (json::iterator it = single_rule.begin(); it != single_rule.end(); ++it) {  <-- alternative to the below line
                // ternary rule handler
                for (auto &rule_values : single_rule_set) {
                    std::string rule = rule_values[0].get<std::string>();
                    // rule_values[1] == Rule value 1
                    // rule_values[2] == Rule value 2
                    rule_counter++;

                    if (rule.size() != 1) {
                        // Error because Rule class only accepts a char right now.
                        fprintf(stderr, "Parse warning: Ignoring rule: \"%s\" was expecting a 1 character rule. %lu given.", rule.c_str(), rule.size());
                    }

                    else if (rule_values.size() == 1) {
                        Rule single_rule(static_cast<char>(rule[0]), "", "");
                        rule_set.push_back(single_rule);
                    }
                    else if (rule_values.size() == 2) {
                        Rule single_rule(static_cast<char>(rule[0]), rule_values[1].get<std::string>(), "");
                        rule_set.push_back(single_rule);
                    }
                    else if (rule_values.size() == 3) {
                        Rule single_rule(static_cast<char>(rule[0]), rule_values[1].get<std::string>(), rule_values[2].get<std::string>());
                        rule_set.push_back(single_rule);
                    }
                    else {
                        fprintf(stderr, "Parse error: object %d contain a rule with too many 'values'. an array of 1 to 3 (string) values expected. %lu given\n", rule_set_counter, rule_values.size());
                        exit(EXIT_FAILURE);
                    }
                }
                rule_objects.push_back(rule_set);
            }

            // Enumerate rules
            std::ifstream fin_test(input_file);
            std::string file_line;
            int carriage_return_test = 0;
            while(std::getline(fin_test, file_line))
            {
                // Remove all carriage return
                if(carriage_return_test > 10) {
                    break;
                }
                if(file_line.find('\r') != std::string::npos) {
                    fprintf(stderr, R"(Parse error: wordlist contains carriage returns "\r" aka "^M".)");
                    exit(EXIT_FAILURE);
                }
                carriage_return_test++;
            }

            std::ios::sync_with_stdio(false);  // disable syncing with stdio
            std::ifstream fin;
            char stream_buffer[4096];
            fin.rdbuf()->pubsetbuf(stream_buffer, sizeof(stream_buffer)); // set buffer for reading characters
            fin.open(input_file);
            while(std::getline(fin, file_line)) {
                if(file_line.empty()) {
                    continue;
                }
                for(std::vector<Rule>& rule_set : rule_objects) {
                    if(rule_set[0].rule == ':') {
                        std::cout << file_line << '\n';
                        continue;
                    }
                    std::string new_plain { file_line };
                    for(Rule& rule_item : rule_set) {
                        rule_item.process(new_plain);
                    }
                    if(file_line != new_plain) {
                        std::cout << new_plain << '\n';
                    }
                }
            }
        } else if (vm.count("wordlist")) {
            fprintf(stderr, "Rules parameter missing.\n");

        } else if (vm.count("rules")) {
            fprintf(stderr, "Wordlist parameter missing.\n");
        } else {
            std::cout << desc << '\n';
        }
    }
    catch (const error &ex) {
        std::cerr << ex.what() << '\n';
    }
    return 0;
}
