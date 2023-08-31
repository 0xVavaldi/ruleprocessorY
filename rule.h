//
// Created by Vavaldi on 14-8-2021.
//

#ifndef FIRSTPROJECT_RULE_H
#define FIRSTPROJECT_RULE_H


#include <string>
#include <functional>
#include <algorithm>

class Rule {
public:
    char rule;
    std::string rule_value_1;
    std::string rule_value_2;
    std::function<void(std::string &)> rule_processor;
    bool invalid_rule;

    Rule(char input_rule, const std::string &input_rule_value_1, const std::string &input_rule_value_2);
    void print(bool error=false);
    void process(std::string& plaintext);
    std::function<void(std::string&)> build_rule_processor();
    bool operator==(const Rule& rhs) const;

    static int rule_identify(char);

private:
    [[nodiscard]] bool validate_rule() const;
};

#endif //FIRSTPROJECT_RULE_H
