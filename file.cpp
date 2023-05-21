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
#include <sstream>
#include <iterator>
#include <ctime>
#include <curl/curl.h>
#include <unistd.h>

#define AES_BLOCK_SIZE 16

using namespace std;

vector<string> commandHistory;

void StrTokenizer(char *line, char **argv);
void myExecvp(char **argv);
void addToHistory(const string &command);
void printCommandHistory();
void encryptFile(const string &filePath, const string &key);
void decryptFile(const string &filePath, const string &key);
void downloadFile(const std::string &url);
void displayDiskUsage();
void getCPUStats();
void getCPUUsage();
void getSwapMemoryUsage();
void getRAMUsage();
void encryptFile(const string& filePath, const string& key);
void decryptFile(const string& filePath, const string& key);
void downloadFile(const std::string& url);
void changeTerminalColor(char *color);
void displayDiskUsage();
void printEnvironment();


vector<vector<char>> board(3, vector<char>(3, ' '));
char currentPlayer = 'X';



void drawBoard()
{
    cout << "-------------" << endl;
    for (int i = 0; i < 3; i++)
    {
        cout << "| ";
        for (int j = 0; j < 3; j++)
        {
            cout << board[i][j] << " | ";
        }
        cout << endl << "-------------" << endl;
    }
}

void makeMove(int row, int col)
{
    if (row < 0 || row >= 3 || col < 0 || col >= 3 || board[row][col] != ' ')
    {
        cout << "Invalid move. Try again." << endl;
        return;
    }

    board[row][col] = currentPlayer;
    currentPlayer = (currentPlayer == 'X') ? 'O' : 'X';

    drawBoard();
}

bool checkWin()
{
    // Check rows
    for (int i = 0; i < 3; i++)
    {
        if (board[i][0] == board[i][1] && board[i][1] == board[i][2] && board[i][0] != ' ')
        {
            return true;
        }
    }

    // Check columns
    for (int i = 0; i < 3; i++)
    {
        if (board[0][i] == board[1][i] && board[1][i] == board[2][i] && board[0][i] != ' ')
        {
            return true;
        }
    }

    // Check diagonals
    if ((board[0][0] == board[1][1] && board[1][1] == board[2][2] && board[0][0] != ' ') ||
        (board[0][2] == board[1][1] && board[1][1] == board[2][0] && board[0][2] != ' '))
    {
        return true;
    }

    return false;
}

bool checkDraw()
{
    for (int i = 0; i < 3; i++)
    {
        for (int j = 0; j < 3; j++)
        {
            if (board[i][j] == ' ')
            {
                return false;
            }
        }
    }
    return true;
}


void changeTerminalColor(char *color)
{
    if (strcmp(color, "rgb") == 0)
    {
        // Seamless transition through all colors (e.g., RGB)
        for (int r = 0; r < 256; r++)
        {
            for (int g = 0; g < 256; g++)
            {
                for (int b = 0; b < 256; b++)
                {
                    char command[50];
                    sprintf(command, "tput setaf %d", r);
                    system(command);
                    sprintf(command, "tput setab %d", b);
                    system(command);
                    sprintf(command, "clear");
                    system(command);
                    usleep(100000); // Delay for smooth transition (adjust as needed)
                }
            }
        }
    }
    else
    {
        // Set terminal color based on the provided color input
        char command[50];
        sprintf(command, "tput setaf %s", color);
        system(command);
    }
}

void playTicTacToe()
{
    cout << "Starting Tic-Tac-Toe..." << endl;
    drawBoard();

    while (true)
    {
        int row, col;
        cout << "Player " << currentPlayer << ", enter your move (row col): ";
        cin >> row >> col;

        makeMove(row, col);

        if (checkWin())
        {
            cout << "Player " << currentPlayer << " wins!" << endl;
            break;
        }

        if (checkDraw())
        {
            cout << "It's a draw!" << endl;
            break;
        }
    }
}
int main()
{
    bool rgbMode = false;
    char input[250];
    char *argv[250];
    cout<<R"(

      ___         ___           ___                         ___                                       ___              
     /\  \       /\  \         /\  \         _____         /\  \         _____                       /\__\             
    /::\  \     /::\  \       /::\  \       /::\  \       /::\  \       /::\  \                     /:/ _/_            
   /:/\:\__\   /:/\:\__\     /:/\:\  \     /:/\:\  \     /:/\:\  \     /:/\:\  \                   /:/ /\__\           
  /:/ /:/  /  /:/ /:/  /    /:/  \:\  \   /:/ /::\__\   /:/ /::\  \   /:/ /::\__\   ___     ___   /:/ /:/ _/_          
 /:/_/:/  /  /:/_/:/__/___ /:/__/ \:\__\ /:/_/:/\:|__| /:/_/:/\:\__\ /:/_/:/\:|__| /\  \   /\__\ /:/_/:/ /\__\         
 \:\/:/  /   \:\/:::::/  / \:\  \ /:/  / \:\/:/ /:/  / \:\/:/  \/__/ \:\/:/ /:/  / \:\  \ /:/  / \:\/:/ /:/  /         
  \::/__/     \::/~~/~~~~   \:\  /:/  /   \::/_/:/  /   \::/__/       \::/_/:/  /   \:\  /:/  /   \::/_/:/  /          
   \:\  \      \:\~~\        \:\/:/  /     \:\/:/  /     \:\  \        \:\/:/  /     \:\/:/  /     \:\/:/  /           
    \:\__\      \:\__\        \::/  /       \::/  /       \:\__\        \::/  /       \::/  /       \::/  /            
     \/__/       \/__/         \/__/         \/__/         \/__/         \/__/         \/__/         \/__/             
               ___           ___                       ___           ___           ___                                 
              /\__\         /\  \                     /\__\         /\  \         /\  \                                
             /:/ _/_        \:\  \       ___         /:/ _/_       |::\  \       /::\  \                               
            /:/ /\__\        \:\  \     /\__\       /:/ /\  \      |:|:\  \     /:/\:\  \                              
           /:/ /:/ _/_   _____\:\  \   /:/__/      /:/ /::\  \   __|:|\:\  \   /:/ /::\  \                             
          /:/_/:/ /\__\ /::::::::\__\ /::\  \     /:/__\/\:\__\ /::::|_\:\__\ /:/_/:/\:\__\                            
          \:\/:/ /:/  / \:\~~\~~\/__/ \/\:\  \__  \:\  \ /:/  / \:\~~\  \/__/ \:\/:/  \/__/                            
           \::/_/:/  /   \:\  \        ~~\:\/\__\  \:\  /:/  /   \:\  \        \::/__/                                 
            \:\/:/  /     \:\  \          \::/  /   \:\/:/  /     \:\  \        \:\  \                                 
             \::/  /       \:\__\         /:/  /     \::/  /       \:\__\        \:\__\                                
              \/__/         \/__/         \/__/       \/__/         \/__/         \/__/                                

)";
    while (true)
    {
        cout << "ProbableEnigma-> ";
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

        else if (strcmp(argv[0], "color") == 0) // Check if the command is for changing the color
        {
            if (argv[1] != NULL)
            {
                if (strcmp(argv[1], "rgb") == 0)
                {
                    rgbMode = true; // Enable RGB mode
                    changeTerminalColor(argv[1]);
                }
                else
                {
                    rgbMode = false; // Disable RGB mode
                    changeTerminalColor(argv[1]);
                }
            }
            else
            {
                cout << "Invalid color input!" << endl;
            }
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
        else if (strcmp(argv[0], "tictactoe") == 0)
        {
            playTicTacToe();
            continue;
        }
        else if (strcmp(argv[0], "cpuuse") == 0)
        {
            getCPUUsage();
            continue;
        }
        else if (strcmp(argv[0], "cputemp") == 0)
        {
            getCPUStats();
            continue;
        }
        else if (strcmp(argv[0], "memswap") == 0)
        {
            getSwapMemoryUsage();
            continue;
        }
        else if (strcmp(argv[0], "memram") == 0) {
            getRAMUsage();
            continue;
        }
         else if (strcmp(argv[0], "export") == 0)
        {
            if (argv[1] != NULL)
            {
                exportVariable(argv[1]);
            }
            else
            {
                cout << "Please provide the variable to export." << endl;
            }
            continue;
        }
        else if (strcmp(argv[0], "env") == 0)
        {
            printEnvironment();
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

void addToHistory(const string &command)
{
    commandHistory.push_back(command);
}

void printCommandHistory()
{
    for (const string &command : commandHistory)
    {
        cout << command << endl;
    }
}

void getCPUStats()
{
    ifstream file("/sys/class/thermal/thermal_zone0/temp");
    if (file)
    {
        string line;
        getline(file, line);
        float temp = stof(line) / 1000.0;
        cout << "CPU Temperature: " << temp << "°C" << endl;
        file.close();
    }
    else
    {
        cout << "Failed to open CPU temperature file." << endl;
    }
}

void getCPUUsage()
{
    FILE *pipe = popen("top -bn1 | grep Cpu", "r");
    if (pipe)
    {
        char buffer[128];
        if (fgets(buffer, sizeof(buffer), pipe))
        {
            string cpuUsage(buffer);
            size_t pos = cpuUsage.find_last_of(" ");
            if (pos != string::npos)
            {
                cout << "CPU Usage: " << cpuUsage;
            }
        }
        pclose(pipe);
    }
    else
    {
        cout << "Failed to get CPU usage." << endl;
    }
}

void getSwapMemoryUsage()
{
    ifstream file("/proc/meminfo");
    if (file)
    {
        string line;
        while (getline(file, line))
        {
            if (line.find("SwapTotal") != string::npos)
            {
                stringstream ss(line);
                string name;
                int value;
                ss >> name >> value;
                cout << "Swap Memory: " << value << " kB" << endl;
                break;
            }
        }
        file.close();
    }
    else
    {
        cout << "Failed to open /proc/meminfo file." << endl;
    }
}

void getRAMUsage()
{
    ifstream file("/proc/meminfo");
    if (file)
    {
        string line;
        vector<string> tokens;
        while (getline(file, line))
        {
            tokens.clear();
            istringstream iss(line);
            copy(istream_iterator<string>(iss), istream_iterator<string>(), back_inserter(tokens));
            if (tokens.size() >= 3 && tokens[0] == "MemTotal:")
            {
                int total = stoi(tokens[1]);
                if (tokens[2] == "kB")
                    total /= 1024;
                cout << "Total RAM: " << total << " MB" << endl;
            }
            else if (tokens.size() >= 3 && tokens[0] == "MemAvailable:")
            {
                int available = stoi(tokens[1]);
                if (tokens[2] == "kB")
                    available /= 1024;
                cout << "Available RAM: " << available << " MB" << endl;
                break;
            }
        }
        file.close();
    }
    else
    {
        cout << "Failed to open /proc/meminfo file." << endl;
    }
}

void encryptFile(const string &filePath, const string &key)
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
    outputFile.write(reinterpret_cast<const char *>(iv), AES_BLOCK_SIZE);

    AES_KEY aesKey;
    AES_set_encrypt_key(reinterpret_cast<const unsigned char *>(key.c_str()), 128, &aesKey);

    unsigned char inData[AES_BLOCK_SIZE];
    unsigned char outData[AES_BLOCK_SIZE];

    // Encrypt and write the input file content to the output file
    while (inputFile.read(reinterpret_cast<char *>(inData), AES_BLOCK_SIZE))
    {
        AES_encrypt(inData, outData, &aesKey);
        outputFile.write(reinterpret_cast<const char *>(outData), AES_BLOCK_SIZE);
    }

    // Pad the last block if needed
    if (inputFile.gcount() > 0 && inputFile.gcount() < AES_BLOCK_SIZE)
    {
        memset(inData + inputFile.gcount(), AES_BLOCK_SIZE - inputFile.gcount(), AES_BLOCK_SIZE - inputFile.gcount());
        AES_encrypt(inData, outData, &aesKey);
        outputFile.write(reinterpret_cast<const char *>(outData), AES_BLOCK_SIZE);
    }

    inputFile.close();
    outputFile.close();

    cout << "Encryption completed. Encrypted file: " << filePath + ".enc" << endl;
}

void decryptFile(const string &filePath, const string &key)
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
    inputFile.read(reinterpret_cast<char *>(iv), AES_BLOCK_SIZE);

    AES_KEY aesKey;
    AES_set_decrypt_key(reinterpret_cast<const unsigned char *>(key.c_str()), 128, &aesKey);

    unsigned char inData[AES_BLOCK_SIZE];
    unsigned char outData[AES_BLOCK_SIZE];

    // Decrypt and write the input file content to the output file
    while (inputFile.read(reinterpret_cast<char *>(inData), AES_BLOCK_SIZE))
    {
        AES_decrypt(inData, outData, &aesKey);
        outputFile.write(reinterpret_cast<const char *>(outData), AES_BLOCK_SIZE);
    }

    // Remove padding from the last block if needed
    if (inputFile.gcount() > 0 && inputFile.gcount() < AES_BLOCK_SIZE)
    {
        unsigned char paddingLength = inData[AES_BLOCK_SIZE - 1];
        outputFile.write(reinterpret_cast<const char *>(outData), AES_BLOCK_SIZE - paddingLength);
    }

    inputFile.close();
    outputFile.close();

    cout << "Decryption completed. Decrypted file: " << filePath + ".dec" << endl;
}

void displayDiskUsage()
{
    string command = "df -h";
    string result;
    FILE *pipe = popen(command.c_str(), "r");
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

size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    // Write the downloaded content to a file
    std::ofstream outputFile(static_cast<const char *>(userp), std::ios::binary | std::ios::app);
    outputFile.write(static_cast<const char *>(contents), size * nmemb);
    outputFile.close();

    return size * nmemb;
}

void downloadFile(const std::string &url)
{
    // Extract the filename from the URL
    std::string filename = url.substr(url.find_last_of('/') + 1);

    // Create a CURL handle
    CURL *curl = curl_easy_init();
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

void printEnvironment()
{
    char* env = getenv("PATH");
    cout << "Environment variable PATH: " << env << endl;
}