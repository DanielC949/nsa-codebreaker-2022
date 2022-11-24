#include <iostream>
#include <fstream>
#include <chrono>

#include "evplib.h"
#include "keytester.h"

#include "uuid_key.cpp"

// g++ -Wall -std=c++11 -O3 main.cpp keytester.cpp evplib.cpp -o main -lcrypto
int main(int argc, char* argv[])
{
    init_tester("../important_data.pdf.enc", "../important_data_DEC.pdf");
    auto start_time = std::chrono::high_resolution_clock::now();

    int res = test();

    std::chrono::duration<double, std::milli> ms = std::chrono::high_resolution_clock::now() - start_time;
    std::cout << "Elapsed sec: " << ms.count() / 1000 << std::endl;
    report_nkeys_tested();
    return res;
}
