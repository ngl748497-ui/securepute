using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace computer_secure.Scoring
{
    internal class Score
    {
        static List<string> knownIPC2 = new List<string>();
        public static void InitializeCNCList()
        {
            knownIPC2.Add("212.227.76.105");
            knownIPC2.Add("86.54.42.146");
            knownIPC2.Add("150.136.72.116");
            knownIPC2.Add("13.62.134.6");
            knownIPC2.Add("194.69.162.205");
            knownIPC2.Add("66.179.189.111");
            knownIPC2.Add("147.139.213.171");
            knownIPC2.Add("45.63.99.50");
            knownIPC2.Add("35.181.65.155");
            knownIPC2.Add("45.138.159.140");
        }
        public static int ScoreThreat(string action, string affected)
        {
            InitializeCNCList();
            //Console.WriteLine($"[DEBUG ScoreThreat] Action: '{action}', Affected: '{affected}'");
            int score = 0;
            bool is_malicious = false;
            switch (action)
            {
                case "NetworkSend":

                    if (knownIPC2.Contains(affected))
                    {
                        score += 5;
                    }
                    break;


                case "NtCreateFile":
                case "NtWriteFile":

                    if (affected.Contains("C:\\Windows\\System32", StringComparison.OrdinalIgnoreCase) ||
                        affected.Contains("C:\\Windows\\SysWOW64", StringComparison.OrdinalIgnoreCase))
                    {
                        score += 4;
                    }
                    break;

                case "NtCreateThread":
                case "NtCreateProcess":
                    score += 5;
                    break;

                case "NtCreateKey":
                case "NtOpenKey":
                case "NtSetValueKey":
                    if (affected.Contains("Run") || affected.Contains("RunOnce"))
                    {
                        score += 2;
                    }
                    break;

                default:
                    break;


            }
            if(score > 12) { is_malicious = true; }
            else { is_malicious = false; }

            if (score > 0)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[SCORE] Scored {score} for Action: '{action}' on Object: '{affected}'");
                Console.ResetColor();
            }
            return score;
        }
    }
}
