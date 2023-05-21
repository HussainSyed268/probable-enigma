#include <iostream>
#include <string.h>
#include <unistd.h>
#include <cstdlib>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <vector>
#include <string>
#include <algorithm>
#include <fstream>
#include <openssl/aes.h>
#include <openssl/rand.h>

#define AES_BLOCK_SIZE 16

using namespace std;

vector<string> commandHistory;

void StrTokenizer(char *line, char **argv);
void myExecvp(char **argv);
void addToHistory(const string& command);
void printCommandHistory();
void encryptFile(const string& filePath, const string& key);
void decryptFile(const string& filePath, const string& key);
void convertToPDF(const string& filePath);

int main()
{
    char input[250];
    char *argv[250];

    while (true)
    {
        cout << "cwushell-> ";
        cin.getline(input, 250);
        StrTokenizer(input, argv);

        if (strcmp(argv[0], "exit") == 0)
        {
            break;
        }
        else if (strcmp(argv[0], "cd") == 0)
        {
            if (chdir(argv[1]) != 0)
            {
                cout << "Failed to change directory" << endl;
            }
            continue;
        }
        else if (strcmp(argv[0], "history") == 0)
        {
            printCommandHistory();
            continue;
        }
        else if (strcmp(argv[0], "encrypt") == 0)
        {
            if (argv[1] != NULL)
            {
                if (argv[2] != NULL)
                {
                    encryptFile(argv[1], argv[2]);
                }
                else
                {
                    cout << "Please provide the encryption key." << endl;
                }
            }
            else
            {
                cout << "Please provide the file path to encrypt." << endl;
            }
            continue;
        }
        else if (strcmp(argv[0], "decrypt") == 0)
        {
            if (argv[1] != NULL)
            {
                if (argv[2] != NULL)
                {
                    decryptFile(argv[1], argv[2]);
                }
                else
                {
                    cout << "Please provide the decryption key." << endl;
                }
            }
            else
            {
                cout << "Please provide the file path to decrypt." << endl;
            }
            continue;
        }
        else if (strcmp(argv[0], "convert") == 0)
        {
            if (argv[1] != NULL)
            {
                convertToPDF(argv[1]);
            }
            else
            {
                cout << "Please provide the file path to convert." << endl;
            }
            continue;
        }

        myExecvp(argv);
        addToHistory(input);
    }

    return 0;
}

void myExecvp(char **argv)
{
    pid_t pid;
    int status;
    int childStatus;
    pid = fork();
    if (pid == 0)
    {
        childStatus = execvp(*argv, argv);
        if (childStatus < 0)
        {
            cout << "ERROR: wrong input" << endl;
        }
        exit(0);
    }
    else if (pid < 0)
    {
        cout << "something went wrong!" << endl;
    }
    else
    {
        int status;
        waitpid(pid, &status, 0);
    }
}

void StrTokenizer(char *input, char **argv)
{
    char *stringTokenized;
    stringTokenized = strtok(input, " ");
    while (stringTokenized != NULL)
    {
        *argv++ = stringTokenized;
        stringTokenized = strtok(NULL, " ");
    }

    *argv = NULL;
}

void addToHistory(const string& command)
{
    commandHistory.push_back(command);
}

void printCommandHistory()
{
    int count = 1;
    for (const auto& command : commandHistory)
    {
        cout << count << ". " << command << endl;
        count++;
    }
}

void encryptFile(const string& filePath, const string& key)
{
    ifstream inputFile(filePath, ios::binary);
    if (!inputFile)
    {
        cout << "Failed to open the input file." << endl;
        return;
    }

    ofstream outputFile(filePath + ".enc", ios::binary);
    if (!outputFile)
    {
        cout << "Failed to create the encrypted file." << endl;
        return;
    }

    // Generate random IV
    unsigned char iv[AES_BLOCK_SIZE];
    RAND_bytes(iv, AES_BLOCK_SIZE);

    // Write the IV to the output file
    outputFile.write(reinterpret_cast<const char*>(iv), AES_BLOCK_SIZE);

    AES_KEY aesKey;
    AES_set_encrypt_key(reinterpret_cast<const unsigned char*>(key.c_str()), 128, &aesKey);

    unsigned char inData[AES_BLOCK_SIZE];
    unsigned char outData[AES_BLOCK_SIZE];

    // Encrypt and write the input file content to the output file
    while (inputFile.read(reinterpret_cast<char*>(inData), AES_BLOCK_SIZE))
    {
        AES_encrypt(inData, outData, &aesKey);
        outputFile.write(reinterpret_cast<const char*>(outData), AES_BLOCK_SIZE);
    }

    // Pad the last block if needed
    if (inputFile.gcount() > 0 && inputFile.gcount() < AES_BLOCK_SIZE)
    {
        memset(inData + inputFile.gcount(), AES_BLOCK_SIZE - inputFile.gcount(), AES_BLOCK_SIZE - inputFile.gcount());
        AES_encrypt(inData, outData, &aesKey);
        outputFile.write(reinterpret_cast<const char*>(outData), AES_BLOCK_SIZE);
    }

    inputFile.close();
    outputFile.close();

    cout << "Encryption completed. Encrypted file: " << filePath + ".enc" << endl;
}

void decryptFile(const string& filePath, const string& key)
{
    ifstream inputFile(filePath, ios::binary);
    if (!inputFile)
    {
        cout << "Failed to open the input file." << endl;
        return;
    }

    ofstream outputFile(filePath + ".dec", ios::binary);
    if (!outputFile)
    {
        cout << "Failed to create the decrypted file." << endl;
        return;
    }

    // Read the IV from the input file
    unsigned char iv[AES_BLOCK_SIZE];
    inputFile.read(reinterpret_cast<char*>(iv), AES_BLOCK_SIZE);

    AES_KEY aesKey;
    AES_set_decrypt_key(reinterpret_cast<const unsigned char*>(key.c_str()), 128, &aesKey);

    unsigned char inData[AES_BLOCK_SIZE];
    unsigned char outData[AES_BLOCK_SIZE];

    // Decrypt and write the input file content to the output file
    while (inputFile.read(reinterpret_cast<char*>(inData), AES_BLOCK_SIZE))
    {
        AES_decrypt(inData, outData, &aesKey);
        outputFile.write(reinterpret_cast<const char*>(outData), AES_BLOCK_SIZE);
    }

    // Remove padding from the last block if needed
    if (inputFile.gcount() > 0 && inputFile.gcount() < AES_BLOCK_SIZE)
    {
        unsigned char padSize = outData[AES_BLOCK_SIZE - 1];
        outputFile.write(reinterpret_cast<const char*>(outData), AES_BLOCK_SIZE - padSize);
    }

    inputFile.close();
    outputFile.close();

    cout << "Decryption completed. Decrypted file: " << filePath + ".dec" << endl;
}

void convertToPDF(const string& filePath)
{
    string command = "libreoffice --headless --convert-to pdf " + filePath + " --outdir " + filePath.substr(0, filePath.find_last_of('/'));
    int status = system(command.c_str());
    if (status == 0)
    {
        cout << "Conversion to PDF completed." << endl;
    }
    else
    {
        cout << "Failed to convert to PDF." << endl;
    }
}
