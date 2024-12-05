#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>

// Функция для чтения файла в строку
std::string ReadFile(const std::string& filepath) {
    std::ifstream input(filepath, std::ios::binary);
    if (!input) {
        throw std::runtime_error("Unable to open file: " + filepath);
    }
    std::ostringstream buffer;
    buffer << input.rdbuf();
    return buffer.str();
}

// Функция для вычисления SHA-512 хэша
std::string ComputeHash(const std::string& data) {
    std::string result;
    CryptoPP::SHA512 hashFunction;
    CryptoPP::StringSource(data, true,
        new CryptoPP::HashFilter(hashFunction,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(result), false
            )
        )
    );
    return result;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <input_file>" << std::endl;
        return 1;
    }

    try {
        std::string inputFile = argv[1];
        std::string fileData = ReadFile(inputFile); 
        std::string hashValue = ComputeHash(fileData); 
        std::cout << "Computed SHA-512 Hash: " << hashValue << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
