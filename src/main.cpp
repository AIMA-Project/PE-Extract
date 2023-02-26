/**
 * @author Drew Wheeler
 * @date 2023-02-26
 * 
 */

#include "BinManip.hpp"
#include "HeaderExtract.hpp"

int main (int argc, char** argv)
{
    std::string file = "testfiles/mongofiles.exe";
    HeaderInfo hf (file);
    if (hf.analyze_file())
        hf.print_coff();
    else
        std::cerr << "\nWas unable to open file." << std::endl;

    return 0;
}