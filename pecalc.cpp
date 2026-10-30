
#include <windows.h>
#include <conio.h>

#include <cstdint>
#include <cstring>
#include <cctype>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

// ------------------------------------------------------------
// Convert an integer to a hexadecimal string.
// ------------------------------------------------------------

static std::string hex_string(uint64_t value)
{
    std::ostringstream output;

    output << "0x"
           << std::uppercase
           << std::hex
           << value;

    return output.str();
}

// ------------------------------------------------------------
// Parse an address.
//
// Accepts:
//   81C93F
//   081C93F
//   0x81C93F
//   0X81C93F
//
// Input is always interpreted as hexadecimal.
// ------------------------------------------------------------

static bool parse_address(const std::string& input,
                          uint64_t& value)
{
    try
    {
        std::string number = input;

        // Remove an optional 0x or 0X prefix.
        if (number.size() >= 2 &&
            number[0] == '0' &&
            (number[1] == 'x' || number[1] == 'X'))
        {
            number.erase(0, 2);
        }

        if (number.empty())
        {
            return false;
        }

        // Always interpret the address as hexadecimal.
        size_t used = 0;

        value = std::stoull(number, &used, 16);

        return used == number.size();
    }
    catch (...)
    {
        return false;
    }
}

// ------------------------------------------------------------
// PE section information.
// ------------------------------------------------------------

struct SectionInfo
{
    std::string name;

    uint64_t virtual_address = 0;
    uint64_t virtual_size = 0;

    uint64_t raw_offset = 0;
    uint64_t raw_size = 0;
};

// ------------------------------------------------------------
// Main program.
// ------------------------------------------------------------

int main(int argc, char* argv[])
{
    std::cout
        << "\n"
        << "============================================\n"
        << "          PE Address Calculator\n"
        << "============================================\n\n";

    // --------------------------------------------------------
    // Check command-line arguments.
    // --------------------------------------------------------

    if (argc != 2)
    {
        std::cout
            << "Usage:\n"
            << "  " << argv[0] << " <file.exe>\n\n";

        return 1;
    }

    const std::string filename = argv[1];

    // --------------------------------------------------------
    // Open the executable.
    // --------------------------------------------------------

    std::ifstream file(filename, std::ios::binary);

    if (!file)
    {
        std::cerr
            << "ERROR: Unable to open file:\n"
            << filename << "\n\n";

        return 1;
    }

    // --------------------------------------------------------
    // Determine file size.
    // --------------------------------------------------------

    file.seekg(0, std::ios::end);

    std::streamoff file_size = file.tellg();

    if (file_size < 0)
    {
        std::cerr << "ERROR: Unable to determine file size.\n";
        return 1;
    }

    file.seekg(0, std::ios::beg);

    // --------------------------------------------------------
    // Read DOS header.
    // --------------------------------------------------------

    IMAGE_DOS_HEADER dos_header{};

    file.read(
        reinterpret_cast<char*>(&dos_header),
        sizeof(dos_header)
    );

    if (!file || dos_header.e_magic != IMAGE_DOS_SIGNATURE)
    {
        std::cerr << "ERROR: Invalid DOS header.\n";
        return 1;
    }

    if (dos_header.e_lfanew < 0)
    {
        std::cerr << "ERROR: Invalid PE header offset.\n";
        return 1;
    }

    // --------------------------------------------------------
    // Read PE signature.
    // --------------------------------------------------------

    file.seekg(dos_header.e_lfanew, std::ios::beg);

    DWORD signature = 0;

    file.read(
        reinterpret_cast<char*>(&signature),
        sizeof(signature)
    );

    if (!file || signature != IMAGE_NT_SIGNATURE)
    {
        std::cerr << "ERROR: Invalid PE signature.\n";
        return 1;
    }

    // --------------------------------------------------------
    // Read COFF file header.
    // --------------------------------------------------------

    IMAGE_FILE_HEADER file_header{};

    file.read(
        reinterpret_cast<char*>(&file_header),
        sizeof(file_header)
    );

    if (!file)
    {
        std::cerr << "ERROR: Unable to read COFF header.\n";
        return 1;
    }

    // --------------------------------------------------------
    // Read optional header magic.
    // --------------------------------------------------------

    WORD optional_magic = 0;

    file.read(
        reinterpret_cast<char*>(&optional_magic),
        sizeof(optional_magic)
    );

    if (!file)
    {
        std::cerr << "ERROR: Unable to read optional header.\n";
        return 1;
    }

    // --------------------------------------------------------
    // Determine PE architecture and image base.
    // --------------------------------------------------------

    uint64_t image_base = 0;

    bool is_64bit = false;

    if (optional_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        is_64bit = true;

        IMAGE_OPTIONAL_HEADER64 optional_header{};

        file.seekg(
            dos_header.e_lfanew +
            sizeof(DWORD) +
            sizeof(IMAGE_FILE_HEADER),
            std::ios::beg
        );

        file.read(
            reinterpret_cast<char*>(&optional_header),
            sizeof(optional_header)
        );

        if (!file ||
            file_header.SizeOfOptionalHeader < sizeof(optional_header))
        {
            std::cerr << "ERROR: Invalid PE32+ optional header.\n";
            return 1;
        }

        image_base = optional_header.ImageBase;
    }
    else if (optional_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        IMAGE_OPTIONAL_HEADER32 optional_header{};

        file.seekg(
            dos_header.e_lfanew +
            sizeof(DWORD) +
            sizeof(IMAGE_FILE_HEADER),
            std::ios::beg
        );

        file.read(
            reinterpret_cast<char*>(&optional_header),
            sizeof(optional_header)
        );

        if (!file ||
            file_header.SizeOfOptionalHeader < sizeof(optional_header))
        {
            std::cerr << "ERROR: Invalid PE32 optional header.\n";
            return 1;
        }

        image_base = optional_header.ImageBase;
    }
    else
    {
        std::cerr << "ERROR: Unsupported optional header format.\n";
        return 1;
    }

    // --------------------------------------------------------
    // Display executable information.
    // --------------------------------------------------------

    std::cout
        << "File:         " << filename << "\n"
        << "File Size:    " << file_size << " bytes\n"
        << "Architecture: "
        << (is_64bit ? "x64 (PE32+)" : "x86 (PE32)")
        << "\n"
        << "Image Base:   " << hex_string(image_base)
        << "\n"
        << "Sections:     " << file_header.NumberOfSections
        << "\n\n";

    // --------------------------------------------------------
    // Read section headers.
    // --------------------------------------------------------

    std::vector<SectionInfo> sections;

    file.seekg(
        dos_header.e_lfanew +
        sizeof(DWORD) +
        sizeof(IMAGE_FILE_HEADER) +
        file_header.SizeOfOptionalHeader,
        std::ios::beg
    );

    for (WORD i = 0; i < file_header.NumberOfSections; ++i)
    {
        IMAGE_SECTION_HEADER section_header{};

        file.read(
            reinterpret_cast<char*>(&section_header),
            sizeof(section_header)
        );

        if (!file)
        {
            std::cerr << "ERROR: Unable to read section headers.\n";
            return 1;
        }

        SectionInfo section;

        char section_name[9] = {};

        std::memcpy(
            section_name,
            section_header.Name,
            8
        );

        section.name = section_name;

        section.virtual_address = section_header.VirtualAddress;
        section.virtual_size = section_header.Misc.VirtualSize;

        section.raw_offset = section_header.PointerToRawData;
        section.raw_size = section_header.SizeOfRawData;

        sections.push_back(section);
    }

    // --------------------------------------------------------
    // Ask user which address format they want to enter.
    // No Enter key required.
    // --------------------------------------------------------

    std::cout
        << "Address Type:\n\n"
        << "  [V] Virtual Address (VA)\n"
        << "  [R] Relative Virtual Address (RVA)\n\n"
        << "Select: " << std::flush;

    char address_type = '\0';

    while (true)
    {
        address_type = static_cast<char>(
            std::toupper(static_cast<unsigned char>(_getch()))
        );

        if (address_type == 'V' || address_type == 'R')
        {
            std::cout << address_type << "\n";
            break;
        }
    }

    // --------------------------------------------------------
    // Request address.
    // --------------------------------------------------------

    std::cout
        << "\nEnter address (hexadecimal): ";

    std::string address_input;

    std::cin >> address_input;

    uint64_t entered_address = 0;

    if (!parse_address(address_input, entered_address))
    {
        std::cerr << "\nERROR: Invalid hexadecimal address.\n";
        return 1;
    }

    // --------------------------------------------------------
    // Convert VA to RVA if necessary.
    // --------------------------------------------------------

    uint64_t rva = entered_address;

    if (address_type == 'V')
    {
        std::cout
            << "\nVA to RVA Conversion:\n"
            << "  VA:        " << hex_string(entered_address)
            << "\n"
            << "  ImageBase: " << hex_string(image_base)
            << "\n";

        if (entered_address < image_base)
        {
            std::cerr
                << "\nERROR: VA is below the executable ImageBase.\n";

            return 1;
        }

        rva = entered_address - image_base;

        std::cout
            << "  RVA:       " << hex_string(rva)
            << "\n";
    }
    else
    {
        std::cout
            << "\nRVA entered directly: "
            << hex_string(rva)
            << "\n";
    }

    // --------------------------------------------------------
    // Check every section.
    // --------------------------------------------------------

    std::cout
        << "\n"
        << "============================================\n"
        << "              Section Analysis\n"
        << "============================================\n";

    unsigned int valid_mappings = 0;

    for (const auto& section : sections)
    {
        std::cout
            << "\n--------------------------------------------\n"
            << "Section: " << section.name << "\n"
            << "--------------------------------------------\n";

        std::cout
            << "Virtual Address:  "
            << hex_string(section.virtual_address) << "\n"

            << "Virtual Size:     "
            << hex_string(section.virtual_size) << "\n"

            << "Raw File Offset:  "
            << hex_string(section.raw_offset) << "\n"

            << "Raw Data Size:    "
            << hex_string(section.raw_size) << "\n";

        // Check whether the RVA is inside this section's
        // virtual extent.

        if (rva < section.virtual_address)
        {
            std::cout
                << "Status: NOT IN THIS SECTION\n";

            continue;
        }

        uint64_t delta = rva - section.virtual_address;

        if (delta >= section.virtual_size)
        {
            std::cout
                << "Status: NOT IN THIS SECTION\n";

            continue;
        }

        // RVA belongs to this section's virtual extent.

        std::cout
            << "Section Offset:   "
            << hex_string(delta) << "\n";

        // Check whether this virtual address has
        // corresponding raw file data.

        if (delta >= section.raw_size)
        {
            std::cout
                << "Status: VIRTUAL-ONLY REGION\n"
                << "This RVA has no corresponding raw file data.\n";

            continue;
        }

        // Calculate file offset.

        uint64_t file_offset = section.raw_offset + delta;

        std::cout
            << "Calculation:\n"
            << "  Raw Offset + Section Offset\n"
            << "  " << hex_string(section.raw_offset)
            << " + "
            << hex_string(delta)
            << "\n";

        std::cout
            << "  File Offset = "
            << hex_string(file_offset)
            << "\n";

        // Check whether calculated offset exists in file.

        if (file_offset >= static_cast<uint64_t>(file_size))
        {
            std::cout
                << "Status: RAW DATA EXTENDS BEYOND FILE\n";

            continue;
        }

        std::cout
            << "Status: VALID FILE MAPPING\n";

        ++valid_mappings;
    }

    // --------------------------------------------------------
    // Final summary.
    // --------------------------------------------------------

    std::cout
        << "\n"
        << "============================================\n"
        << "                  Summary\n"
        << "============================================\n\n";

    std::cout
        << "Entered Address: "
        << hex_string(entered_address) << "\n"

        << "Address Type:    "
        << (address_type == 'V' ? "VA" : "RVA") << "\n"

        << "RVA:             "
        << hex_string(rva) << "\n"

        << "Valid Mappings:  "
        << valid_mappings << "\n";

    if (valid_mappings == 0)
    {
        std::cout
            << "\nNo valid file offset was found.\n";
    }
    else
    {
        std::cout
            << "\nOne or more valid file mappings were found.\n";
    }

    std::cout << "\n";

    return 0;
}
