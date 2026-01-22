#ifndef MYHEADER_H
#define MYHEADER_H

#include <string>
#include <iostream>

inline std::string get_message() {
    return "Hello from header with absolute path!";
}

inline int calculate_sum(int a, int b) {
    return a + b;
}

inline void print_header_info() {
    std::cout << "Header file: " << __FILE__ << std::endl;
}

#endif
