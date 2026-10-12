#ifndef MYHEADER_H
#define MYHEADER_H

#include <string>
#include <iostream>

inline std::string get_message() {
    return "Hello from a header reached by an absolute -I path!";
}

inline void print_header_info() {
    std::cout << "Header file: " << __FILE__ << std::endl;
}

#endif
