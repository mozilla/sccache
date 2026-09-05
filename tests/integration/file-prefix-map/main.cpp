// Source for the -ffile-prefix-map test, see scripts/test-file-prefix-map.sh.
//
// Both the path of this file and the path of the header reach the object file,
// through __FILE__ and through the debug info, so that the test would notice if
// -ffile-prefix-map were not doing its job.  ROOT, by contrast, is a path the
// compiler bakes in exactly as it is written on the command line.
#include <iostream>
#include "myheader.h"

#ifndef ROOT
#define ROOT "unset"
#endif

int main() {
    std::cout << "Main file: " << __FILE__ << std::endl;
    std::cout << "Root: " << ROOT << std::endl;
    std::cout << get_message() << std::endl;
    print_header_info();
    return 0;
}
