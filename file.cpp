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
#include <ctime>
#include <curl/curl.h>


#define AES_BLOCK_SIZE 16

using namespace std;

vector<string> commandHistory;

void StrTokenizer(char *line, char **argv);
void myExecvp(char **argv);
void addToHistory(const string& command);
void printCommandHistory();
void encryptFile(const string& filePath, const string& key);
void decryptFile(const string& filePath, const string& key);
void downloadFile(const std::string& url);
void displayDiskUsage();

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
        else if (strcmp(argv[0], "diskusage") == 0)
        {
            displayDiskUsage();
            continue;
        }
        else if (strcmp(argv[0], "download") == 0)
{
    if (argv[1] != NULL)
    {
        downloadFile(argv[1]);
    }
    else
    {
        std::cout << "Please provide the URL to download." << std::endl;
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
    for (const string& command : commandHistory)
    {
        cout << command << endl;
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
        unsigned char paddingLength = inData[AES_BLOCK_SIZE - 1];
        outputFile.write(reinterpret_cast<const char*>(outData), AES_BLOCK_SIZE - paddingLength);
    }

    inputFile.close();
    outputFile.close();

    cout << "Decryption completed. Decrypted file: " << filePath + ".dec" << endl;
}

void displayDiskUsage()
{
    string command = "df -h";
    string result;
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe)
    {
        cout << "Failed to execute command." << endl;
        return;
    }

    char buffer[128];
    while (!feof(pipe))
    {
        if (fgets(buffer, 128, pipe) != NULL)
        {
            result += buffer;
        }
    }

    pclose(pipe);

    cout << result << endl;
}


size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp)
{
    // Write the downloaded content to a file
    std::ofstream outputFile(static_cast<const char*>(userp), std::ios::binary | std::ios::app);
    outputFile.write(static_cast<const char*>(contents), size * nmemb);
    outputFile.close();

    return size * nmemb;
}

void downloadFile(const std::string& url)
{
    // Extract the filename from the URL
    std::string filename = url.substr(url.find_last_of('/') + 1);

    // Create a CURL handle
    CURL* curl = curl_easy_init();
    if (curl)
    {
        // Set the URL to download from
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

        // Set the write callback function
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);

        // Set the filename as user data
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, filename.c_str());

        // Perform the download
        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK)
        {
            std::cout << "Failed to download file: " << curl_easy_strerror(res) << std::endl;
        }

        // Clean up the CURL handle
        curl_easy_cleanup(curl);

        std::cout << "Download completed. File saved as: " << filename << std::endl;
    }
    else
    {
        std::cout << "Failed to initialize CURL." << std::endl;
    }
}