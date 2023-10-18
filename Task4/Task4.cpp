#include <iostream>﻿
#include <string>
#include "Dll2.h"
#include <windows.h>
#include <cstdlib>
#include <vector>
#include <fstream> 

class EncryptionLibrary {
private:
    HINSTANCE handle;
    typedef std::string(*encrypt_ptr_t)(std::string, int);
    typedef std::string(*decrypt_ptr_t)(std::string, int);
    encrypt_ptr_t encrypt_ptr;
    decrypt_ptr_t decrypt_ptr;

public:
    EncryptionLibrary() : handle(nullptr), encrypt_ptr(nullptr), decrypt_ptr(nullptr) {
        handle = LoadLibrary(TEXT("Dll2.dll"));
        if (handle != nullptr && handle != INVALID_HANDLE_VALUE) {
            encrypt_ptr = (encrypt_ptr_t)GetProcAddress(handle, "Encrypt");
            decrypt_ptr = (decrypt_ptr_t)GetProcAddress(handle, "Decrypt");
        }
    }

    ~EncryptionLibrary() {
        if (handle) {
            FreeLibrary(handle);
        }
    }

    std::string encrypt(const std::string& input, int key) {
        if (encrypt_ptr) {
            return encrypt_ptr(input, key);
        }
        return "Function 'Encrypt' not found";
    }

    std::string decrypt(const std::string& input, int key) {
        if (decrypt_ptr) {
            return decrypt_ptr(input, key);
        }
        return "Function 'Decrypt' not found";
    }
};

class FileO {


public:
    FileO() {}
    EncryptionLibrary EncryptLib;


    void Read(std::string fileName, int key, std::string choice) {
        std::ifstream file(fileName);
        if (!file.is_open()) {
            std::cerr << "Error: Could not open file '" << fileName << "'." << std::endl;
            return;
        }
        std::string line;

        if (choice=="en")
        {
            while (getline(file, line)) {
                
                    line=EncryptLib.encrypt(line,key);
                    ArrayEncrypted.push_back(line);
                    std::cout << line << std::endl;
            }
        }
        if (choice == "de") {
            while (getline(file, line)) {
                
                line=EncryptLib.decrypt(line, key);
                ArrayDecrypted.push_back(line);
                std::cout << line<< std::endl;
            }
        } 
    }

    void Clear(std::string choice) {
        if (choice == "Encrypted")
        {

            ArrayEncrypted.clear();
        }
        else
        {
            ArrayDecrypted.clear();
        }
    }

    void WriteEncrypted(std::string name) {
        std::ofstream file(name);
        for (int i = 0; i < ArrayEncrypted.size(); i++)
        {
            file << ArrayEncrypted[i] << std::endl;
        }
        file.close();
    }

    void WriteDecrypted(std::string name) {
        std::ofstream file(name);
        for (int i = 0; i < ArrayDecrypted.size(); i++)
        {
            file << ArrayEncrypted[i] << std::endl;
        }
        file.close();
    }

private:
    std::vector<std::string> ArrayDecrypted;
    std::vector<std::string> ArrayEncrypted;
};


int main()
{

    FileO FileManager;
    FileManager.Read("C:/Users/Давід/source/repos/Task4/Task4/toEncrypt.txt.txt", 3, "en");
    /*

    std::string choice = argv[1];
    int key = std::atoi(argv[2]);
    std::string str = argv[3];

    HINSTANCE handle = LoadLibrary(TEXT("Dll2.dll"));
    if (handle == nullptr || handle == INVALID_HANDLE_VALUE)
    {
        std::cout << "Lib not found" << std::endl;
        return 1;
    }

    if (choice == "encrypt")
    {
        encrypt_ptr_t encrypt_ptr = (encrypt_ptr_t)GetProcAddress(handle, "Encrypt");
        if (encrypt_ptr == nullptr)
        {
            std::cout << "Function 'Encrypt' not found" << std::endl;
            return 1;
        }
        std::cout << encrypt_ptr(str, key) << std::endl;
    }
    else if (choice == "decrypt")
    {
        decrypt_ptr_t decrypt_ptr = (decrypt_ptr_t)GetProcAddress(handle, "Decrypt");
        if (decrypt_ptr == nullptr)
        {
            std::cout << "Function 'Decrypt' not found" << std::endl;
            return 1;
        }
        std::cout << decrypt_ptr(str, key) << std::endl;
    }
    FreeLibrary(handle);
    */

    return 0;
}