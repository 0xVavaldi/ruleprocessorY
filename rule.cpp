//
// Created by Vavaldi on 14-8-2021.
//

#include "rule.h"
#include <cctype>
#include <iostream>


Rule::Rule(const char input_rule, const std::string& input_rule_value_1, const std::string& input_rule_value_2) {
    rule = input_rule ;
    rule_value_1 = input_rule_value_1;
    rule_value_2 = input_rule_value_2;
    rule_processor = build_rule_processor();
    if(!validate_rule()) {
        fprintf(stderr, "Parse warning: rule \"%c%s%s\" is an invalid rule.\n", rule, rule_value_1.c_str(), rule_value_2.c_str());
//        exit(EXIT_FAILURE);
    };
}

bool Rule::validate_rule() const {
    switch(rule) {
        case ':': return true;
        case 'l':
        case 'u':
        case 'c':
        case 'C':
        case 't':
        case 'r':
        case 'd':
        case 'f':
        case '{':
        case '}':
        case '[':
        case ']':
        case 'k':
        case 'K':
        case 'q':
            if(!(rule_value_1.empty() && rule_value_2.empty())) { // Unary operations should not have rule values.
                return false;
            }
            return true;
        case 'T':
        case 'p':
        case 'D':
        case 'Z':
        case 'z':
        case '$':
        case '^':
        case '<':
        case '>':
        case '_':
        case '\'':
        case '!':
        case '/':
            if(rule_value_1.empty() || !rule_value_2.empty()) { // Binary operations should not have 2 rule values.
                return false;
            }
            return true;
        case '@':
            if(rule_value_1.empty() || !rule_value_2.empty()) { // Binary operations should not have 2 rule values.
                return false;
            }
            if(rule_value_1.size() > 1) {

            }
        case 's':
        case 'S':
        case 'x':
        case 'O':
        case 'o':
        case 'i':
            if(rule_value_1.empty() || rule_value_2.empty()) {
                return false;
            }
            return true;
        default:
            return false;
    }
}

std::function<void(std::string&)> Rule::build_rule_processor() {
    int int_value_1, int_value_2;
    switch(rule) {
        case 'l':
            return [](std::string& plaintext){
                transform(plaintext.begin(), plaintext.end(), plaintext.begin(), ::tolower);
            };

        case 'u':
            return [](std::string& plaintext){
                transform(plaintext.begin(), plaintext.end(), plaintext.begin(), ::toupper);
            };

        case 'c':
            return [](std::string& plaintext){
                transform(plaintext.begin(), plaintext.end(), plaintext.begin(), ::tolower);
                plaintext[0] = char(toupper(plaintext[0]));
            };

        case 'C':
            return [](std::string& plaintext){
                transform(plaintext.begin(), plaintext.end(), plaintext.begin(), ::toupper);
                plaintext[0] = char(tolower(plaintext[0]));
            };

        case 't':
            return [](std::string& plaintext){
                for (char& i : plaintext) {
                    if(islower(i)) {
                        i = char(toupper(i));
                    } else if (isupper(i)) {
                        i = char(tolower(i));
                    }
                }
            };

        case 'q':
            return [](std::string& plaintext){
                for(std::string::size_type i = 0; i < plaintext.size(); ++i) {
                    plaintext.insert(i+1, 1, plaintext[i]);
                    i++;
                }
            };

        case 'r':
            return [](std::string& plaintext){
                reverse(plaintext.begin(), plaintext.end());
            };

        case 'k':
            return [](std::string& plaintext){
                if(plaintext.length() < 2) return;
                char i = plaintext[0];
                plaintext[0] = plaintext[1];
                plaintext[1] = i;
            };

        case 'K':
            return [](std::string& plaintext){
                if(plaintext.length() < 2) return;
                char i = plaintext.back();
                plaintext[plaintext.length() - 1] = plaintext[plaintext.length() - 2];
                plaintext[plaintext.length() - 2] = i;
            };

        case 'd':
            return [](std::string& plaintext){
                plaintext += plaintext;
            };

        case 'f':
            return [](std::string& plaintext){
                std::string copy = plaintext; // Extra copy for operations
                reverse(copy.begin(), copy.end());
                plaintext += copy;
            };

        case '{':
            return [](std::string& plaintext){
                std::rotate(plaintext.begin(), plaintext.begin() + 1, plaintext.end());
            };

        case '}':
            return [](std::string& plaintext){
                reverse(plaintext.begin(), plaintext.begin()+1);
                reverse(plaintext.begin()+1, plaintext.end());
                reverse(plaintext.begin(), plaintext.end());
            };

        case '[':
            return [](std::string& plaintext){
                plaintext.erase(0, 1);
            };

        case ']':
            return [](std::string& plaintext){
		if(plaintext.size() >= 1) {
                    plaintext.erase(plaintext.size()-1, 1);
                }
            };

        case 'T':
            int_value_1 = stoi(rule_value_1); // character location
            return [char_location = int_value_1](std::string& plaintext){
                if(char_location < 0 || char_location > plaintext.size()-1) {
                    return;
                }

                if(islower(plaintext[char_location])) {
                    plaintext[char_location] = char(toupper(plaintext[char_location]));
                } else if (isupper(plaintext[char_location])) {
                    plaintext[char_location] = char(tolower(plaintext[char_location]));
                }
            };

        case 'p':
            int_value_1 = stoi(rule_value_1);
            return [duplicate_count=int_value_1](std::string& plaintext){
                std::string copy = plaintext;
                for(int i=0; i < duplicate_count; i++) {
                    plaintext += copy;
                }
            };

        case 'D':
            int_value_1 = stoi(rule_value_1); // character location
            if(int_value_1 < 0) {
                break;
            }
            return [char_location=int_value_1](std::string& plaintext){
                if(char_location > plaintext.size()-1) {
                    return;
                }
                plaintext.erase(char_location, 1);
            };

        case 'z':
            int_value_1 = stoi(rule_value_1); // duplicate amount
            return [duplicate_count=int_value_1](std::string& plaintext){
                for(int i=0; i < duplicate_count; i++) {
                    plaintext.insert(0, plaintext.substr(0,1));
                }
            };

        case 'Z':
            int_value_1 = stoi(rule_value_1); // duplicate amount
            return [duplicate_count=int_value_1](std::string& plaintext){
                for(int i=0; i < duplicate_count; i++) {
                    plaintext += plaintext.substr(plaintext.size()-1, 1);
                }
            };

        case '\'':
            int_value_1 = stoi(rule_value_1); // duplicate amount
            if(int_value_1 < 0) {
                break;
            }
            return [duplicate_count=int_value_1](std::string& plaintext){
                if(duplicate_count > plaintext.size()-1) {
                    return;
                }
                plaintext = plaintext.substr(0, duplicate_count);
            };

        case 's':
            if(rule_value_1.size() == 1 && rule_value_2.size() == 1) {
                return [rule_value_1=rule_value_1[0], rule_value_2=rule_value_2[0]](std::string& plaintext){
                    std::replace(plaintext.begin(), plaintext.end(), rule_value_1, rule_value_2);
                };
            } else {
                return [rule_value_1=rule_value_1, rule_value_2=rule_value_2](std::string& plaintext){
                    size_t index = 0;
                    while(true) {
                        index = plaintext.find(rule_value_1, index);
                        if(index == std::string::npos) break;
                        plaintext = plaintext.replace(index, rule_value_1.size(), rule_value_2);
                        index += rule_value_2.size();
                    }
                };
            }

        case 'S':
            return [rule_value_1=rule_value_1, rule_value_2=rule_value_2](std::string& plaintext){
                if(plaintext.find(rule_value_1) != std::string::npos) {
                    plaintext = plaintext.replace(plaintext.find(rule_value_1), rule_value_1.size(), rule_value_2);
                }
            };

        case '$':
            return [rule_value_1=rule_value_1](std::string& plaintext){
                plaintext.append(rule_value_1);
            };

        case '^':
            return [rule_value_1=rule_value_1](std::string& plaintext){
                plaintext.insert(0, rule_value_1);
            };

        case '@':
            return [rule_value_1=rule_value_1[0]](std::string& plaintext){
                plaintext.erase(std::remove(plaintext.begin(), plaintext.end(), rule_value_1), plaintext.end());
            };

        case 'i':
            int_value_1 = stoi(rule_value_1); // insert location
            if(int_value_1 < 0) break;

            return [insert_location=int_value_1, rule_value_2=rule_value_2](std::string& plaintext){
                if(insert_location > plaintext.size()-1) {
                    return;
                }
                plaintext.insert(insert_location, rule_value_2);
            };

        case 'O':
            int_value_1 = stoi(rule_value_1); // start location
            int_value_2 = stoi(rule_value_2); // delete amount
            if(int_value_1 < 0 || int_value_2 < 0) break;

            return [start_loc=int_value_1, delete_amount=int_value_2](std::string& plaintext){
                if(start_loc > plaintext.size()-1 || plaintext.size() == 0) {
                    return;
                }
                if(start_loc + delete_amount > plaintext.size()) {
                    plaintext.erase(start_loc, plaintext.size()-start_loc); // Delete until end.
                } else {
                    plaintext.erase(start_loc, delete_amount);
                }
            };

        case 'x':
            int_value_1 = stoi(rule_value_1); // start location
            int_value_2 = stoi(rule_value_2); // delete amount
            if(int_value_1 < 0 || int_value_2 < 0) break;

            return [start_loc=int_value_1, keep_amount=int_value_2](std::string& plaintext){
                if(start_loc > plaintext.size()-1) {
                    return;
                }

                if((start_loc + keep_amount) <= plaintext.size()) {
                    plaintext.erase(start_loc + keep_amount, plaintext.size());
                    plaintext.erase(0, start_loc); // Delete from start to start of rule
                } else {
                    plaintext.erase(0, start_loc); // Delete from start to start of rule
                }
            };

        case '<':
            int_value_1 = stoi(rule_value_1);
            return [reject_count=int_value_1](std::string& plaintext){
                if(reject_count < plaintext.size()) {
                    return;
                }
                plaintext = "";
            };

        case '>':
            int_value_1 = stoi(rule_value_1);
            return [reject_count=int_value_1](std::string& plaintext){
                if(reject_count > plaintext.size()) {
                    return;
                }
                plaintext = "";
            };

        case '_':
            int_value_1 = stoi(rule_value_1);
            return [reject_count=int_value_1](std::string& plaintext){
                if(reject_count == plaintext.size()) {
                    plaintext = "";
                }
            };

        case '!':  // Reject plains which contain rule_value_1
            return [rule_value_1=rule_value_1](std::string& plaintext){
                if (plaintext.find(rule_value_1) != std::string::npos) {
                    plaintext = "";
                }
            };

        case '/':  // Reject plains which do not contain char X
            return [rule_value_1=rule_value_1](std::string& plaintext){
                if (plaintext.find(rule_value_1) == std::string::npos) {
                    plaintext = "";
                }
            };
    }
    return [](std::string& plaintext){};
}

void Rule::process(std::string& plaintext) {
    return rule_processor(plaintext);
}

void Rule::display() const {
    fprintf(stdout,
        "Rule: \"%c\"\n"
        "\tValue 1: %s\n"
        "\tValue 2: %s\n",
        rule,
        rule_value_1.c_str(),
        rule_value_2.c_str()
    );
}
