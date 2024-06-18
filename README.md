# Reverse Shell Using Stolen Token

This project demonstrates a reverse shell implementation using Winsock and WinAPI. A reverse shell is a common technique used in cyberattacks to gain control over a computer remotely. In this project, we utilize the `CreateProcessWithTokenW` function to launch a CMD shell on a target machine.

## How It Works

1. **ObfuscationProcess**: Initially, the `ObfuscationProcess` function runs the calculator application (`calc.exe`) as a test case. This step is for testing the functionality rather than the main purpose of the project.

2. **Initializing Winsock**: The `WSAStartup` function initializes the Windows Socket API and specifies the required version (2.2).

3. **Creating a Socket**: The `WSASocket` function creates a TCP socket.

4. **Establishing a Connection**: The `WSAConnect` function establishes a connection to the specified IP address and port number.

5. **Managing the Shell**: Once connected, data exchange occurs over the created socket. A token for the `winlogon.exe` process is created using the `CreateProcessWithTokenW` function, and a `cmd.exe` shell is launched using this token.

6. **Data Exchange**: Data from and to the created CMD shell is transmitted over the socket.

## Requirements

- Windows operating system
- Visual Studio (for development)

## How to Use

1. Clone the repository to your local machine.
2. Open the project in Visual Studio.
3. Build the project to generate the executable.
4. Run the executable (`RevShell.exe`).
5. The program will attempt to connect to a specified IP address (`192.168.1.103`) and port (`1337`).
6. Ensure that a listening server is set up to receive the reverse shell connection.

## Notes

- This project is intended for educational purposes and should be used responsibly and legally.
- The `CreateProcessWithTokenW` function is used with the `LOGON_WITH_PROFILE` flag to launch the shell.
- Error handling and cleanup are included to manage resources properly.

For detailed documentation and explanations, refer to the source code comments and additional resources on Windows API functions.
