//CODE QUAN TRỌNG

using computer_secure.EventTracing;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Diagnostics.Tracing.StackSources;
using Microsoft.Windows.EventTracing.Disk;
using System;
using System.Drawing;
using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace computer_secure.EventTracing;
class TraceMain
{
    private const string SessionName = "SystemActivityMonitorSession";

    //Dictionary dict = new Dictionary;
    string syscall;
    public class TraceOutput
    {
        [JsonPropertyName("processName")]
        public string ProcessName { get; set; }

        [JsonPropertyName("syscallName")]
        public string SyscallName { get; set; }

        [JsonPropertyName("affectedObject")]
        public string AffectedObject { get; set; }

        [JsonPropertyName("calledTime")]
        public int CalledTime { get; set; }
    }
    private const string OutputFileName = "trace_source/trace_result.json";
    private static readonly Dictionary<EventKey, int> _eventCounts = new();
    private static readonly object _lock = new();

    public record EventKey(string ProcessName, string SyscallName, string AffectedObject);

    public static void PrepareTrace()
    {
        if (!TraceEventSession.IsElevated() ?? false)
        {
            Console.WriteLine("Please run this program under Administrator permission");
            Console.ReadKey();
            return;
        }

        Console.WriteLine("Monitoring..");
        Console.WriteLine("Control-C to stop the process");

        using (var session = new TraceEventSession(SessionName))
        {

            var kernelKeywords =
                KernelTraceEventParser.Keywords.Registry |
                //KernelTraceEventParser.Keywords.SystemCall |
                KernelTraceEventParser.Keywords.NetworkTCPIP |
                KernelTraceEventParser.Keywords.FileIO |
                KernelTraceEventParser.Keywords.FileIOInit |
                KernelTraceEventParser.Keywords.ImageLoad |
                KernelTraceEventParser.Keywords.Process;

            session.EnableKernelProvider(kernelKeywords);


            using (var source = new ETWTraceEventSource(SessionName, TraceEventSourceType.Session))
            {
                var kernelParser = new KernelTraceEventParser(source);

                kernelParser.RegistryCreate += OnRegistryEvent;
                kernelParser.RegistrySetValue += OnRegistryEvent;
                kernelParser.RegistryDelete += OnRegistryEvent;
                kernelParser.TcpIpSend += OnNetworkSend;
                kernelParser.UdpIpSend += OnNetworkSend;
                kernelParser.FileIORead += OnDiskIORead;
                kernelParser.FileIOWrite += OnDiskIORead;
                kernelParser.ImageLoad += OnImageLoad;
                kernelParser.ProcessStart += OnProcessStart;
                //source.Kernel.PerfInfoSysClEnter += OnSysCallEvent;
                var processingTask = Task.Run(() =>
                {
                    source.Process();
                });

                Task.Delay(60 * 1000).Wait(); // Chờ 60 giây

                session.Flush();

                session.Stop();


            }
            WriteDataToJson();
        }
    }
    private static void AddOrUpdateEvent(EventKey key)
    {
        lock (_lock)
        {
            _eventCounts.TryGetValue(key, out int currentCount);
            _eventCounts[key] = currentCount + 1;
        }
    }
    private static void OnProcessStart(ProcessTraceData data)
    {
        // Ta có thể giả định map tên sự kiện "ProcessStart" sang Syscall mong muốn
        string syscall = "NtCreateProcess";

        Console.ForegroundColor = ConsoleColor.Yellow;
        // In ra cả Process ID của tiến trình cha để dễ theo dõi
        Console.WriteLine($"[PROCESS] Event: ProcessStart | New Process: {data.ProcessName} ({data.ProcessID}) | Parent PID: {data.ParentID}");
        Console.ResetColor();

        // Ghi lại thông tin process cha để thấy rõ mối quan hệ
        var affectedObject = $"Parent PID: {data.ParentID}";
        var key = new EventKey(data.ProcessName, syscall, affectedObject);
        AddOrUpdateEvent(key);
    }
    private static void OnImageLoad(ImageLoadTraceData data)
    {
        string syscall = Dictionary.EtwToSyscallMap[data.EventName];
        Console.ForegroundColor = ConsoleColor.DarkCyan;
        Console.WriteLine($"[DLLFUNCTIONS] Event: {syscall} | Process: {data.ProcessName} ({data.ProcessID})");
        Console.ResetColor();
        var key = new EventKey(data.ProcessName, syscall, data.FileName ?? "N/A");
        AddOrUpdateEvent(key);
    }
    private static void OnRegistryEvent(RegistryTraceData data)
    {
        string syscall = Dictionary.EtwToSyscallMap[data.EventName];
        if (data.ProcessName == "svchost") { }
        else if (data.ProcessName == "msedgewebview2") { }
        else
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"[REGISTRY] Event: {syscall} | Process: {data.ProcessName} ({data.ProcessID}) | Key: {data.KeyName}");
            Console.ResetColor();
        }
        var key = new EventKey(data.ProcessName, syscall, data.KeyName ?? "N/A");
        AddOrUpdateEvent(key);
    }
    public static void OnDiskIORead(FileIOReadWriteTraceData data)
    {
        string syscall = Dictionary.EtwToSyscallMap[data.EventName];
        if (string.IsNullOrEmpty(data.FileName))
        {
            return;
        }
        Console.ForegroundColor = ConsoleColor.Magenta;
        Console.WriteLine($"[FILEIO] FileName: {data.FileName} | Process:{data.ProcessName} | Action:{syscall}");
        Console.ResetColor();
        var key = new EventKey(data.ProcessName, syscall, data.FileName);
        AddOrUpdateEvent(key);
    }



    public static void OnNetworkSend(TraceEvent data)
    {
        string syscall = Dictionary.EtwToSyscallMap[data.EventName];
        int processId = data.ProcessID;
        string processName = data.ProcessName;
        string eventName = data.EventName;


        IPAddress sourceAddr = IPAddress.None, destAddr = IPAddress.None;
        int sourcePort = 0, destPort = 0;
        int size = 0;


        dynamic payload = data;
        sourceAddr = payload.saddr;
        destAddr = payload.daddr;
        sourcePort = payload.sport;
        destPort = payload.dport;
        size = payload.size;

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"[NETWORK]  Event: {syscall} | Process: {processName} ({processId}) | {sourceAddr}:{sourcePort} -> {destAddr}:{destPort} | Size: {size} bytes");
        Console.ResetColor();
        string destination = $"{payload.daddr.ToString()}:{payload.dport.ToString()}";
        var key = new EventKey(data.ProcessName, syscall, destination);
        AddOrUpdateEvent(key);
    }
    private static void WriteDataToJson()
    {
        Console.WriteLine("Writing aggregated data to JSON file...");

        var outputList = _eventCounts.Select(kvp => new TraceOutput
        {
            ProcessName = kvp.Key.ProcessName,
            SyscallName = kvp.Key.SyscallName,
            AffectedObject = kvp.Key.AffectedObject,
            CalledTime = kvp.Value
        }).OrderByDescending(item => item.CalledTime).ToList();

        var options = new JsonSerializerOptions
        {
            WriteIndented = true // Giúp file JSON dễ đọc hơn
        };

        try
        {
            string jsonString = JsonSerializer.Serialize(outputList, options);
            File.WriteAllText(OutputFileName, jsonString);
            Console.WriteLine($"Successfully wrote {outputList.Count} aggregated events to '{OutputFileName}'");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error writing to JSON file: {ex.Message}");
        }
    }
}
