#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/hkdf.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/osrng.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>

// Генерация ключа из пароля и соли
CryptoPP::SecByteBlock DeriveKey(const std::string& password, const CryptoPP::SecByteBlock& salt, size_t keyLength) {
    CryptoPP::SecByteBlock key(keyLength);
    CryptoPP::HKDF<CryptoPP::SHA256> hkdf;
    hkdf.DeriveKey(
        key, key.size(),
        reinterpret_cast<const CryptoPP::byte*>(password.data()), password.size(),
        salt, salt.size(),
        nullptr, 0
    );
    return key;
}

// Шифрование файла
void EncryptFile(const std::string& inputPath, const std::string& outputPath, const std::string& password) {
    // Открытие входного файла
    std::ifstream inputFile(inputPath, std::ios::binary);
    if (!inputFile.is_open()) {
        throw std::runtime_error("Error: Unable to open input file for reading.");
    }

    // Чтение содержимого файла
    std::string plaintext((std::istreambuf_iterator<char>(inputFile)), std::istreambuf_iterator<char>());
    inputFile.close();

    // Генерация соли, IV и ключа
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::SecByteBlock salt(16);
    CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);
    rng.GenerateBlock(salt, salt.size());
    rng.GenerateBlock(iv, iv.size());

    CryptoPP::SecByteBlock key = DeriveKey(password, salt, CryptoPP::AES::DEFAULT_KEYLENGTH);

    // Шифрование
    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption cipher(key, key.size(), iv);
    std::ofstream outputFile(outputPath, std::ios::binary);
    if (!outputFile.is_open()) {
        throw std::runtime_error("Error: Unable to open output file for writing.");
    }

    // Запись соли и IV в файл
    outputFile.write(reinterpret_cast<const char*>(salt.data()), salt.size());
    outputFile.write(reinterpret_cast<const char*>(iv.data()), iv.size());

    // Шифрование и запись данных
    CryptoPP::StringSource(
        plaintext, true,
        new CryptoPP::StreamTransformationFilter(
            cipher,
            new CryptoPP::FileSink(outputFile),
            CryptoPP::BlockPaddingSchemeDef::PKCS_PADDING
        )
    );

    outputFile.close();

    // Отладка
    std::cout << "Encryption completed successfully.\n";
    std::cout << "Salt (hex): ";
    CryptoPP::StringSource(salt, salt.size(), true, new CryptoPP::HexEncoder(new CryptoPP::FileSink(std::cout)));
    std::cout << "\nIV (hex): ";
    CryptoPP::StringSource(iv, iv.size(), true, new CryptoPP::HexEncoder(new CryptoPP::FileSink(std::cout)));
    std::cout << std::endl;
}

// Расшифрование файла
void DecryptFile(const std::string& inputPath, const std::string& outputPath, const std::string& password) {
    // Открытие входного файла
    std::ifstream inputFile(inputPath, std::ios::binary | std::ios::ate);
    if (!inputFile.is_open()) {
        throw std::runtime_error("Error: Unable to open input file for reading.");
    }

    // Проверка размера файла
    std::streamsize fileSize = inputFile.tellg();
    if (fileSize <= 32) { // 16 байт соли + 16 байт IV
        throw std::runtime_error("Error: Input file is too small to contain valid encrypted data.");
    }
    inputFile.seekg(0, std::ios::beg);

    // Чтение соли и IV
    CryptoPP::SecByteBlock salt(16);
    CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);
    inputFile.read(reinterpret_cast<char*>(salt.data()), salt.size());
    inputFile.read(reinterpret_cast<char*>(iv.data()), iv.size());

    // Чтение зашифрованных данных
    std::string ciphertext((std::istreambuf_iterator<char>(inputFile)), std::istreambuf_iterator<char>());
    inputFile.close();

    // Генерация ключа
    CryptoPP::SecByteBlock key = DeriveKey(password, salt, CryptoPP::AES::DEFAULT_KEYLENGTH);

    // Расшифрование
    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption cipher(key, key.size(), iv);
    std::string plaintext;
    CryptoPP::StringSource(
        ciphertext, true,
        new CryptoPP::StreamTransformationFilter(
            cipher,
            new CryptoPP::StringSink(plaintext),
            CryptoPP::BlockPaddingSchemeDef::PKCS_PADDING
        )
    );

    // Запись результата
    std::ofstream outputFile(outputPath, std::ios::binary);
    if (!outputFile.is_open()) {
        throw std::runtime_error("Error: Unable to open output file for writing.");
    }
    outputFile.write(plaintext.data(), plaintext.size());
    outputFile.close();

    // Отладка
    std::cout << "Decryption completed successfully.\n";
    std::cout << "Salt (hex): ";
    CryptoPP::StringSource(salt, salt.size(), true, new CryptoPP::HexEncoder(new CryptoPP::FileSink(std::cout)));
    std::cout << "\nIV (hex): ";
    CryptoPP::StringSource(iv, iv.size(), true, new CryptoPP::HexEncoder(new CryptoPP::FileSink(std::cout)));
    std::cout << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc != 5) {
        std::cerr << "Usage: " << argv[0] << " <encrypt/decrypt> <inputfile> <outputfile> <password>" << std::endl;
        return 1;
    }

    std::string mode = argv[1];
    std::string inputPath = argv[2];
    std::string outputPath = argv[3];
    std::string password = argv[4];

    try {
        if (mode == "encrypt") {
            EncryptFile(inputPath, outputPath, password);
        } else if (mode == "decrypt") {
            DecryptFile(inputPath, outputPath, password);
        } else {
            std::cerr << "Invalid mode. Use 'encrypt' or 'decrypt'." << std::endl;
            return 1;
        }
    } catch (const CryptoPP::Exception& e) {
        std::cerr << "Crypto++ Error: " << e.what() << std::endl;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
