using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.ServiceProcess;
using System.Threading.Tasks;
using System.Timers;
using OSVersionExtension;
using Microsoft.Win32;
using System.IO;
using System.Security.Principal;

namespace RegMod
{
    public partial class RegModService : ServiceBase
    {
        private static int eventId = 1;
        private static EventLog eventLog;
        private static string tempLogFilePath, apiPath;

        public RegModService()
        {
            InitializeComponent();
            eventLog = EventLog;
            if (!EventLog.SourceExists("RegModSvc"))
            {
                EventLog.CreateEventSource("RegModSvc", "RegModLog");
            }
            eventLog.Source = "RegModSvc";
            eventLog.Log = "RegModLog";
        }

        protected static void writeEventLog(string message)
        {
            eventLog.WriteEntry(message, EventLogEntryType.Information, eventId++);
            File.AppendAllText(tempLogFilePath, message + Environment.NewLine);
        }

        protected override void OnStart(string[] args)
        {
            eventId = 1;
            string now = DateTime.Now.ToString("yyyyMMddHHmmss");
            tempLogFilePath = Path.Combine(Path.GetTempPath(), $"RegModSvc_{now}.log");            

            writeEventLog($"Starting service. Log file: {tempLogFilePath}");

            // Set up a timer that triggers every minute.
            Timer timer = new Timer();
            timer.Interval = 1 * 60 * 1000; // 1 minutes
            timer.Elapsed += async (sender, e) => await TimerElapsedEventHandlerAsync(sender, e);
            _ = TimerElapsedEventHandlerAsync(null, null);
            timer.Start();
        }

        private async Task TimerElapsedEventHandlerAsync(object sender, ElapsedEventArgs e)
        {
            writeEventLog(string.Format("Fetching API Path from Registry..."));
            apiPath = getApiPathFromRegistry();
            writeEventLog(string.Format("Fetched API Path from Registry..."));
            try
            {
                writeEventLog(string.Format("Calling URL: {0}", apiPath));
                string jsonData = await GetJsonFromUrlAsync(apiPath);               
                List<Policy> result = JsonConvert.DeserializeObject<List<Policy>>(jsonData);
                foreach (Policy policy in result)
                {
                    WriteToLoggedOnUsers(policy);
                }
            }
            catch (Exception ex)
            {
                writeEventLog($"Error: {ex}");
            }
        }

        private void WriteToLoggedOnUsers(Policy policy)
        {
            foreach (var user in WindowsIdentityHelper.GetLoggedOnUsers())
            {
                try
                {
                    applyRegKey(policy, user.Owner.Value);
                    Console.WriteLine("Updated user " + user.Name + "  SID " + user.Owner.Value);
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.GetBaseException().Message);
                }
            }
        }

        private void WriteRegistry(string value)
        {
            throw new NotImplementedException();
        }

        private string getApiPathFromRegistry()
        {
            apiPath = "https://e83d-4-213-118-130.ngrok-free.app/api/policies";
            string keyPath = @"HKEY_LOCAL_MACHINE\Software\Vshield\Service";
            string valueName = "ApiUrl";

            // Open the registry key
            using (RegistryKey key = Registry.GetValue(keyPath, "", null) as RegistryKey)
            {
                // Check if the key exists
                if (key != null)
                {
                    // Read the registry value
                    apiPath = key.GetValue(valueName).ToString();
                }
            }

            writeEventLog(apiPath);
            return apiPath;
        }

        private void applyRegKey(Policy policy, string sid)
        {
            writeEventLog($"Applying policy: {policy.PolicyUID}");

            string[] osVersions = policy.OperatingSystem.Split(',')
                               .Select(value => $"Windows{value.Trim()}")
                               .ToArray();

            OSVersionExtension.OperatingSystem operatingSystem = OSVersion.GetOperatingSystem();

            if(osVersions.Contains(operatingSystem.ToString()))
            {
                writeEventLog($"Current OS is compatible for policy. Path: {policy.Path}");
                try
                {
                    string rootKey = @"HKEY_USERS\" + sid;
                    string fullKey = $"{rootKey}\\{policy.Path}";

                    switch (policy.RegType)
                    {
                        case "REG_DWORD":
                            writeEventLog("Applying DWORD value...");
                            int intValue;
                            if (int.TryParse(policy.Value, out intValue))
                            {
                                Registry.SetValue(fullKey, policy.Entry, intValue, RegistryValueKind.DWord);
                            }
                            else
                            {
                                writeEventLog($"Invalid REG_DWORD value: {policy.Value}");
                            }
                            break;
                        case "REG_STRING":
                            writeEventLog("Applying String value...");
                            Registry.SetValue(fullKey, policy.Entry, policy.Value, RegistryValueKind.String);
                            break;
                        case "REG_BINARY":
                            writeEventLog($"Applying Binary value...");
                            string val = policy.Value.Replace("hex:", "");
                            writeEventLog($"Val: {val}");
                            var data = val.Split(',')
                                    .Select(x => Convert.ToByte(x, 16))
                                    .ToArray();
                            writeEventLog($"Value: {data}");
                            Registry.SetValue(fullKey, policy.Entry, data, RegistryValueKind.Binary);
                            writeEventLog($"Value written");
                            break;
                        default:
                            string message = $"Unsupported registry value type: {policy.RegType}";
                            writeEventLog($"Error: {message}");
                            break;
                    }
                }
                catch(Exception e)
                {
                    writeEventLog($"Error: {e.Message}");
                }
            }
            else
            {
                writeEventLog($"Current OS is not compatible for policy. Skipping...");
            }
        }

        static async Task<string> GetJsonFromUrlAsync(string url)
        {
            using (HttpClient client = new HttpClient())
            {
                HttpResponseMessage response = await client.GetAsync(url);

                if (response.IsSuccessStatusCode)
                {
                    return await response.Content.ReadAsStringAsync();
                }
                else
                {
                    string message = $"HTTP request failed with status code {response.StatusCode}";
                    writeEventLog($"Error: {message}");
                    throw new HttpRequestException(message);
                }
            }
        }

        protected override void OnStop()
        {
            writeEventLog("Stopping service...");
        }
    }
}
