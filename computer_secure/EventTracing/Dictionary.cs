using PeNet;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
namespace computer_secure.EventTracing;
public static class Dictionary
{
    // Dictionary để lưu bản đồ: Key là địa chỉ (ulong), Value là tên (string)
    public static readonly Dictionary<string, string> EtwToSyscallMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        // File System
        { "FileIO/Create", "NtCreateFile" }, // Bao gồm cả NtOpenFile
        { "FileIO/Read", "NtReadFile" },
        { "FileIO/Write", "NtWriteFile" },
        { "FileIO/DirEnum", "NtQueryDirectoryFile" },

        // Registry
        { "Registry/Create", "NtCreateKey" },
        { "Registry/Open", "NtOpenKey" }, // Bao gồm cả NtOpenKeyEx
        { "Registry/QueryValue", "NtQueryValueKey" },
        { "Registry/EnumerateValue", "NtEnumerateValueKey" },
        { "Registry/EnumerateKey", "NtEnumerateKey" },
        { "Registry/Query", "NtQueryKey" },
        { "Registry/SetValue", "NtSetValueKey" },
        { "Registry/Delete", "NtDeleteKey" },

        // Process & Image Loading
        { "Process/Start", "NtCreateProcess" },
        { "Thread/Start", "NtCreateThread" },
        { "Image/Load", "LdrLoadDll" },

        // Network
        { "TcpIp/Send", "NetworkSend" },
        { "TcpIp/Recv", "NetworkRecv" },
        { "UdpIp/Send", "NetworkSend" },
        { "UdpIp/Recv", "NetworkRecv" }
    };


}