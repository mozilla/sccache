#include <iostream>
#include "myheader.h"

int main() {
    std::cout << "Main file: " << __FILE__ << std::endl;
    std::cout << get_message() << std::endl;
    std::cout << "Sum: " << calculate_sum(5, 3) << std::endl;
    print_header_info();
    return 0;
}
