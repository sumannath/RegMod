using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Security.Policy;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;
using System.Timers;
using OSVersionExtension;
using Microsoft.Win32;

namespace RegMod
{
    public partial class RegModService : ServiceBase
    {
        private int eventId = 1;

        public RegModService()
        {
            InitializeComponent();
            eventLog1 = new System.Diagnostics.EventLog();
            if (!System.Diagnostics.EventLog.SourceExists("MySource"))
            {
                System.Diagnostics.EventLog.CreateEventSource("MySource", "MyNewLog");
            }
            eventLog1.Source = "MySource";
            eventLog1.Log = "MyNewLog";
        }

        protected void writeEventLog(String message)
        {
            eventLog1.WriteEntry(message, EventLogEntryType.Information, eventId++);
        }

        protected override void OnStart(string[] args)
        {
            writeEventLog("In OnStart.");

            // Set up a timer that triggers every minute.
            Timer timer = new Timer();
            timer.Interval = 60 * 1000; // 1 minutes
            timer.Elapsed += async (sender, e) => await TimerElapsedEventHandlerAsync(sender, e);
            timer.Start();
        }

        private async Task TimerElapsedEventHandlerAsync(object sender, ElapsedEventArgs e)
        {
            string url = "https://5805-4-213-118-130.ngrok-free.app/api/policies";

            try
            {
                writeEventLog(String.Format("Calling URL: {0}", url));
                string jsonData = await GetJsonFromUrlAsync(url);               
                List<Policy> result = JsonConvert.DeserializeObject<List<Policy>>(jsonData);
                applyRegKey(result[0]);
            }
            catch (Exception ex)
            {
                writeEventLog($"Error: {ex.Message}");
            }
        }

        private void applyRegKey(Policy policy)
        {
            writeEventLog($"Applying policy: {policy.PolicyUID}");

            string[] osVersions = policy.OperatingSystem.Split(',')
                               .Select(value => $"Windows{value.Trim()}")
                               .ToArray();

            OSVersionExtension.OperatingSystem operatingSystem = OSVersion.GetOperatingSystem();

            if(osVersions.Contains(operatingSystem.ToString()))
            {
                writeEventLog($"Current OS is compatible for policy. Path: {policy.Path}");
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(policy.Path, true))
                {
                    if (key != null)
                    {
                        writeEventLog("Key opened");
                        switch (policy.RegType)
                        {
                            case "REG_DWORD":
                                writeEventLog("In apply value");
                                int intValue;
                                if (int.TryParse(policy.Value, out intValue))
                                {
                                    key.SetValue(policy.Entry, intValue, RegistryValueKind.DWord);
                                }
                                else
                                {
                                    throw new Exception($"Invalid REG_DWORD value: {policy.Value}");
                                }
                                break;

                            // Add more cases for other registry value types if needed

                            default:
                                throw new Exception($"Unsupported registry value type: {policy.RegType}");
                        }
                    }
                    else
                    {
                        throw new Exception($"Unable to create or open registry key: {policy.Path}");
                    }
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
                    throw new HttpRequestException($"HTTP request failed with status code {response.StatusCode}");
                }
            }
        }

        protected override void OnStop()
        {
        }
    }
}
