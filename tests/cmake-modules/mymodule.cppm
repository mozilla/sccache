module;

#include <iostream>

export module mymodule;

export void print_hello_world() {
    std::cout << "Hello, World!" << std::endl;
}

export int add(int a, int b) {
    return a + b;
}