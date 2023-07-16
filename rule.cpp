//
// Created by Vavaldi on 14-8-2021.
//

#include "rule.h"
#include <cctype>
#include <iostream>


Rule::Rule(const char input_rule, const std::string& input_rule_value_1, const std::string& input_rule_value_2) {
    rule_value_1 = input_rule_value_1;
    rule_value_2 = input_rule_value_2;
    rule = input_rule;
    rule_processor = build_rule_processor();
    invalid_rule = false;

    if(!validate_rule()) {
        invalid_rule = true;
    };
}

bool Rule::operator==(const Rule& rhs) const
{
    return (rule == rhs.rule) && (rule_value_1 == rhs.rule_value_1) && (rule_value_2 == rhs.rule_value_2);
    // or, in C++11 (must #include <tuple>)
    // return std::tie(apple, banana) == std::tie(rhs.apple, rhs.banana);
}

int Rule::rule_identify(char rule_char) {
    switch(rule_char) {
        case ':':
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
        case 'E':
            return 1;
        case '@':
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
        case 'y':
        case 'Y':
        case '-':
        case '+':
        case 'e':
        case '.':
        case ',':
        case 'L':
        case 'R':
            return 2;
        case 's':
        case 'S':
        case 'x':
        case 'O':
        case 'o':
        case 'i':
        case '3':
        case '*':
            return 3;
        default:
            return -1;
    }
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
        case 'E':
            if(!(rule_value_1.empty() && rule_value_2.empty())) { // Unary operations should not have rule values.
                return false;
            }
            return true;
        case '@':
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
        case 'y':
        case 'Y':
        case '-':
        case '+':
        case 'e':
        case '.':
        case ',':
        case 'L':
        case 'R':
            if(rule_value_1.empty() || !rule_value_2.empty()) { // Binary operations should not have 2 rule values.
                return false;
            }
            return true;
        case 's':
        case 'S':
        case 'x':
        case 'O':
        case 'o':
        case 'i':
        case '3':
        case '*':
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
    bool value_1_is_numeric = (rule_value_1.find_first_not_of("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ") == std::string::npos);
    bool value_2_is_numeric = (rule_value_2.find_first_not_of("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ") == std::string::npos);

    auto get_number_value = [](const std::string& value)
    {
        std::string alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        size_t index = alphabet.find(value[0]);
        return static_cast<int>(index);
    };


    switch(rule) {
        case ':':
            return [](std::string& plaintext){};
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
                    if(islower(static_cast<unsigned char>(i))) {
                        i = char(toupper(i));
                    } else if (isupper(static_cast<unsigned char>(i))) {
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
                std::swap(plaintext[plaintext.length()-1], plaintext[plaintext.length()-2]);
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
                if(plaintext.empty()) return;
                plaintext += plaintext[0];
                plaintext.erase(0,1);

            };

        case '}':
            return [](std::string& plaintext){
                if(plaintext.empty()) return;
                plaintext.insert(0, 1, plaintext.back());
                plaintext.pop_back();
            };

        case '[':
            return [](std::string& plaintext){
                plaintext.erase(0, 1);
            };

        case ']':
            return [](std::string& plaintext){
		        if(plaintext.empty()) return;
                plaintext.erase(plaintext.size()-1, 1);
            };
        case 'E':
            return [](std::string& plaintext) {
                if(plaintext.empty()) return;
                transform(plaintext.begin(), plaintext.end(), plaintext.begin(), ::tolower);
                plaintext[0] = char(toupper(plaintext[0]));
                for (int i=0; i < plaintext.size(); i++) {
                    if(i-1 < plaintext.size() && plaintext[i] == ' ') {
                        plaintext[i + 1] = char(toupper(plaintext[i + 1]));
                    }
                }
            };

        case 'T':
            if(!value_1_is_numeric) break;
            int_value_1 = get_number_value(rule_value_1); // character location
            return [char_location = int_value_1](std::string& plaintext){
                if(plaintext.empty() || char_location > plaintext.size()-1) {
                    return;
                }
                if(islower(static_cast<unsigned char>(plaintext[char_location]))) {
                    plaintext[char_location] = char(toupper(plaintext[char_location]));
                } else if (isupper(static_cast<unsigned char>(plaintext[char_location]))) {
                    plaintext[char_location] = char(tolower(plaintext[char_location]));
                }
            };

        case 'p':
            if(!value_1_is_numeric) break;
            int_value_1 = get_number_value(rule_value_1);
            return [duplicate_count=int_value_1](std::string& plaintext){
                std::string copy = plaintext;
                for(int i=0; i < duplicate_count; i++) {
                    plaintext += copy;
                }
            };

        case 'D':
            if(!value_1_is_numeric) break;
            int_value_1 = get_number_value(rule_value_1); // character location
            if(int_value_1 < 0) {
                break;
            }
            return [char_location=int_value_1](std::string& plaintext){
                if(plaintext.empty() || char_location > plaintext.size()-1) {
                    return;
                }
                plaintext.erase(char_location, 1);
            };

        case 'z':
            if(!value_1_is_numeric) break;
            int_value_1 = get_number_value(rule_value_1); // duplicate amount
            return [duplicate_count=int_value_1](std::string& plaintext){
                for(int i=0; i < duplicate_count; i++) {
                    plaintext.insert(0, plaintext.substr(0,1));
                }
            };

        case 'Z':
            if(!value_1_is_numeric) break;
            int_value_1 = get_number_value(rule_value_1); // duplicate amount
            return [duplicate_count=int_value_1](std::string& plaintext){
                if(plaintext.empty()) return;
                for(int i=0; i < duplicate_count; i++) {
                    plaintext += plaintext.substr(plaintext.size()-1, 1);
                }
            };

        case '\'':
            if(!value_1_is_numeric) break;
            int_value_1 = get_number_value(rule_value_1); // duplicate amount
            if(int_value_1 < 0) {
                break;
            }
            return [duplicate_count=int_value_1](std::string& plaintext){
                if(plaintext.empty() || duplicate_count > plaintext.size()-1) {
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

        case 'y':
            if(!value_1_is_numeric) break;
            int_value_1 = get_number_value(rule_value_1); // insert location
            if(int_value_1 == 0) break;
            return [rule_value_1=int_value_1](std::string& plaintext){
                plaintext.insert(0, plaintext.substr(0, rule_value_1));
            };

        case 'Y':
            if(!value_1_is_numeric) break;
            int_value_1 = get_number_value(rule_value_1); // insert location
            if(int_value_1 == 0) break;
            return [rule_value_1=int_value_1](std::string& plaintext){
                if(rule_value_1 > plaintext.size()) {
                    plaintext += plaintext;
                } else {
                    plaintext += plaintext.substr(plaintext.size() - rule_value_1);
                }
            };

        case 'L':
            if(!value_1_is_numeric) break;
            int_value_1 = get_number_value(rule_value_1); // insert location
            return [rule_value_1=int_value_1](std::string& plaintext){
                if(rule_value_1 > plaintext.size()) return;
                plaintext[rule_value_1] = plaintext[rule_value_1];
                plaintext[rule_value_1] = static_cast<char>(static_cast<unsigned char>(plaintext[rule_value_1]) << 1);
            };

        case 'R':
            if(!value_1_is_numeric) break;
            int_value_1 = get_number_value(rule_value_1); // insert location
            return [rule_value_1=int_value_1](std::string& plaintext){
                if(rule_value_1 > plaintext.size()) return;
                plaintext[rule_value_1] = plaintext[rule_value_1];
                plaintext[rule_value_1] = static_cast<char>(static_cast<unsigned char>(plaintext[rule_value_1]) >> 1);
            };

        case '-':
            if(!value_1_is_numeric) break;
            int_value_1 = get_number_value(rule_value_1); // insert location
            return [rule_value_1=int_value_1](std::string& plaintext) {
                if(rule_value_1 < plaintext.size()) {
                    plaintext[rule_value_1] = --plaintext[rule_value_1];
                }
            };

        case '+':
            if(!value_1_is_numeric) break;
            int_value_1 = get_number_value(rule_value_1); // insert location
            return [rule_value_1=int_value_1](std::string& plaintext) {
                if(rule_value_1 < plaintext.size()) {
                    plaintext[rule_value_1] = ++plaintext[rule_value_1];
                }
            };

        case '@':
            return [rule_value_1=rule_value_1](std::string& plaintext){
                plaintext.erase(std::remove(plaintext.begin(), plaintext.end(), rule_value_1[0]), plaintext.end());
            };

        case '.':
            if(!value_1_is_numeric) break;
            int_value_1 = get_number_value(rule_value_1); // target location
            return [rule_value_1=int_value_1](std::string& plaintext){
                if(rule_value_1+1 < plaintext.size()) {
                    plaintext[rule_value_1] = plaintext[rule_value_1+1];
                }
            };

        case ',':
            if(!value_1_is_numeric) break;
            int_value_1 = get_number_value(rule_value_1); // target location
            return [rule_value_1=int_value_1](std::string& plaintext){
                if(rule_value_1 < plaintext.size() && rule_value_1 > 0) {
                    plaintext[rule_value_1] = plaintext[rule_value_1-1];
                }
            };

        case 'e':
            return [rule_value_1=rule_value_1](std::string& plaintext){
                if(plaintext.empty()) return;
                transform(plaintext.begin(), plaintext.end(), plaintext.begin(), ::tolower);
                plaintext[0] = char(toupper(plaintext[0]));
                for (int i=0; i < plaintext.size(); i++) {
                    if(i+1 < plaintext.size() && plaintext[i] == rule_value_1[0]) {
                        plaintext[i + 1] = char(toupper(plaintext[i + 1]));
                    }
                }
            };

        case 'i':
            if(!value_1_is_numeric) break;
            int_value_1 = get_number_value(rule_value_1); // insert location
            return [insert_location=int_value_1, rule_value_2=rule_value_2](std::string& plaintext) {
                if(plaintext.empty() || insert_location > plaintext.size()) return;
                plaintext.insert(insert_location, rule_value_2);
            };

        case 'O':
            if(!value_1_is_numeric || !value_2_is_numeric) break;
            int_value_1 = get_number_value(rule_value_1); // start location
            int_value_2 = get_number_value(rule_value_2); // delete amount
            return [start_loc=int_value_1, delete_amount=int_value_2](std::string& plaintext) {
                if(start_loc > plaintext.size()-1 || plaintext.empty()) {
                    return;
                }
                if(start_loc + delete_amount < plaintext.size()) {
                    plaintext.erase(start_loc, delete_amount);
                } else {
//                    plaintext.erase(start_loc, plaintext.size()-start_loc); // Delete until end. // Hashcat behaviour does not delete if it goes out of bound.
                }
            };

        case 'o':
            if(!value_1_is_numeric) break;
            int_value_1 = get_number_value(rule_value_1); // overwrite location
            if(int_value_1 < 0) break;

            return [offset=int_value_1, replace_value=rule_value_2](std::string& plaintext){
                if((offset+replace_value.size()-1) > plaintext.size()-1 || plaintext.empty()) {
                    return;
                }
                for(int i=0; i < replace_value.size(); i++) {
                    plaintext[offset + i] = replace_value[i];
                }
            };

        case '*':
            if(!value_1_is_numeric || !value_2_is_numeric) break;
            int_value_1 = get_number_value(rule_value_1); // swap location 1
            int_value_2 = get_number_value(rule_value_2); // swap location 2
            return [swap_1=int_value_1, swap_2=int_value_2](std::string& plaintext){
                if(plaintext.empty() || swap_1 >= plaintext.size() || swap_2 >= plaintext.size()) return;
                std::swap(plaintext[swap_1], plaintext[swap_2]);
            };

        case 'x':
            if(!value_1_is_numeric || !value_2_is_numeric) break;
            int_value_1 = get_number_value(rule_value_1); // start location
            int_value_2 = get_number_value(rule_value_2); // delete amount
            if(int_value_1 < 0 || int_value_2 < 0) break;
            return [start_loc=int_value_1, keep_amount=int_value_2](std::string& plaintext){
                if(plaintext.empty() || start_loc >= plaintext.size()) {
                    return;
                }
                if((start_loc + keep_amount) <= plaintext.size()) {
                    plaintext.erase(start_loc + keep_amount, plaintext.size()-(start_loc+keep_amount));
                    plaintext.erase(0, start_loc); // Delete from start to start of rule
                }
            };

        case '<':
            if(!value_1_is_numeric) break;
            int_value_1 = get_number_value(rule_value_1);
            return [reject_count=int_value_1](std::string& plaintext){
                if(reject_count < plaintext.size()) {
                    return;
                }
                plaintext = "";
            };

        case '>':
            if(!value_1_is_numeric) break;
            int_value_1 = get_number_value(rule_value_1);
            return [reject_count=int_value_1](std::string& plaintext){
                if(reject_count > plaintext.size()) {
                    return;
                }
                plaintext = "";
            };

        case '_':
            if(!value_1_is_numeric) break;
            int_value_1 = get_number_value(rule_value_1);
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

        case '3':  // Toggle nth instance of a char
            if(!value_1_is_numeric) break;
            int_value_1 = get_number_value(rule_value_1); // character location
            return [rule_instance_of_char = int_value_1, char_value_rule = rule_value_2](std::string& plaintext) {
                if(plaintext.empty()) return;
                int n_th_instance_of_char = -1;
                for(char &char_value : plaintext) {
                    if(n_th_instance_of_char == rule_instance_of_char) {
                        if (islower(static_cast<unsigned char>(char_value))) {
                            char_value = char(toupper(char_value));
                        } else if (isupper(static_cast<unsigned char>(char_value))) {
                            char_value = char(tolower(char_value));
                        }
                        return;
                    }
                    if(char_value == char_value_rule[0]) n_th_instance_of_char++;
                }
            };
    }

    invalid_rule = true;
    return [](std::string& plaintext){};
}

void Rule::process(std::string& plaintext) {
    return rule_processor(plaintext);
}

void Rule::print() {
    std::string rule_1_copy = rule_value_1;
    std::string rule_2_copy = rule_value_2;

    // Replace tabs with hex encoded tabs
    size_t start_pos = rule_1_copy.find('\t');
    if(start_pos != std::string::npos) {
        rule_1_copy.replace(start_pos, 1, "\\x09");
    }
    start_pos = rule_2_copy.find('\t');
    if(start_pos != std::string::npos) {
        rule_2_copy.replace(start_pos, 1, "\\x09");
    }
//    start_pos = rule_1_copy.find(' ');
//    if(start_pos != std::string::npos) {
//        rule_1_copy.replace(start_pos, 1, "\\x20");
//    }
//    start_pos = rule_2_copy.find(' ');
//    if(start_pos != std::string::npos) {
//        rule_2_copy.replace(start_pos, 1, "\\x20");
//    }

    if(Rule::rule_identify(rule) == 3) {
        if(rule_value_1.size() > 1) { // intentionally take rule_value_1 to not take escapes into account.
            start_pos = rule_1_copy.find('/');
            if(start_pos != std::string::npos) {
                rule_1_copy.replace(start_pos, 1, "\\/");
            }

            start_pos = rule_2_copy.find('/');
            if(start_pos != std::string::npos) {
                rule_2_copy.replace(start_pos, 1, "\\/");
            }
            std::cout << rule << '/' << rule_1_copy << '/' << rule_2_copy;
        } else {
            std::cout << rule << rule_1_copy << rule_2_copy;
        }
    } else {
        std::cout << rule << rule_1_copy << rule_2_copy;
    }
}


