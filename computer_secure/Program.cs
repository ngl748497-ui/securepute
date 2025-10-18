using computer_secure.EventTracing;
using computer_secure.Scoring;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Diagnostics.Utilities;
using Microsoft.Windows.EventTracing.Disk;
using System;
using System.Net; 
using System.Text.Json;
using static computer_secure.EventTracing.TraceMain;
namespace computer_secure;
class Program
{
    private const string SessionName = "SystemActivityMonitorSession";
    public static TraceMain tracemain = new TraceMain();
    public static Score scoring = new Score();
    static Dictionary<string, int> processScore = new Dictionary<string, int>();
    static Dictionary<string, (string, float)> processAI = new Dictionary<string, (string, float)>();
    public class ThreatLogEntry
    {

        public string ProcessName { get; set; } = string.Empty;
        public string Action { get; set; } = string.Empty;
        public string AffectedObject { get; set; } = string.Empty;
    }
    public class AIPrediction
    {
        public string process { get; set; } = string.Empty;
        public string prediction { get; set; } = string.Empty;
        public string confidence { get; set; } = string.Empty;
    }
    public static void Main(string[] args)
    {

        TraceMain.PrepareTrace();
        var startInfo = new System.Diagnostics.ProcessStartInfo
        {
            FileName = "python",
            Arguments = "trace_source/predict.py",
            RedirectStandardOutput = true, 
            UseShellExecute = false, 
            CreateNoWindow = true 
        };
        var process = System.Diagnostics.Process.Start(startInfo);
        // Đọc file JSON được copy sẵn trong thư mục build

        string jsonString = File.ReadAllText("trace_source/trace_result.json");
        string prediction_output = File.ReadAllText("trace_source/prediction_output.json");
        var traceEntries = JsonSerializer.Deserialize<List<TraceOutput>>(jsonString);
        var predictionEntries = JsonSerializer.Deserialize<List<AIPrediction>>(prediction_output);
        
        if (traceEntries != null)

        {
            foreach (var entry in traceEntries)
            {
                int score = Score.ScoreThreat(entry.SyscallName, entry.AffectedObject);

                if (!processScore.ContainsKey(entry.ProcessName))
                {
                    processScore[entry.ProcessName] = 0;


                    Console.WriteLine(entry.ProcessName + ": " + score);
                    if (processScore.TryGetValue(entry.ProcessName, out int scores) == false)
                    {
                        processScore.Add(entry.ProcessName, score);
                        //Console.WriteLine(entry.ProcessName + ": " + score);
                    }
                    else if (processScore.TryGetValue(entry.ProcessName, out int scr) && score < scr)
                    {
                        processScore[entry.ProcessName] = scr;
                        //Console.WriteLine(entry.ProcessName + ": " + scr);
                    }

                }
                processScore[entry.ProcessName] += score;
            }
        }

        if (predictionEntries != null)
        {
            foreach (var entry in predictionEntries)
            {
                float confidence_parsed = float.Parse(entry.confidence);
                processAI.Add(entry.process, (entry.prediction, confidence_parsed));
                //Console.WriteLine($"Process: {entry.process}, Prediction: {entry.prediction}, Confidence: {entry.confidence}");
            }
        }

        foreach(var entry in processAI)
        {
            if (processScore.ContainsKey(entry.Key))
            {
                Console.WriteLine($"process: {entry.Key}, {processScore[entry.Key]}, {entry.Value.Item1}, ensure rate {entry.Value.Item2}");
            }
        }

    }
}