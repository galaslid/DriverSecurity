using System;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using System.ServiceProcess;
using System.Diagnostics;
using System.Management;
using System.Security.Cryptography;
using System.IO;
using System.Linq;
using WindowsDriverInfo.Services;
using WindowsDriverInfo.Models;
using System.Text.Json;
using System.Text;

namespace WindowsDriverInfo;

public class DriverInfoProvider
{
    public bool CheckDriverSignatureEnforcement()
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("This function is only available on Windows");

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"System\CurrentControlSet\Control\CodeIntegrity");
            if (key != null)
            {
                var value = key.GetValue("DriverIntegrity");
                return value != null && (int)value == 1;
            }
            return false;
        }
        catch (Exception ex)
        {
            throw new Exception($"Error checking driver signature status: {ex.Message}");
        }
    }

    public string CheckDriverServices()
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("This function is only available on Windows");

        try
        {
            var criticalDriverServices = new[]
            {
                "trustedinstaller",
                "wuauserv",
                "bits",
                "cryptsvc",
                "dot3svc",
                "wcmsvc",
                "storport",
                "spooler"
            };

            var result = new System.Text.StringBuilder();
            result.AppendLine("Critical driver services status:");

            foreach (var serviceName in criticalDriverServices)
            {
                try
                {
                    using var service = new ServiceController(serviceName);
                    result.AppendLine($"Service {serviceName}: {GetServiceStatus(service)}");
                }
                catch (InvalidOperationException)
                {
                    result.AppendLine($"Service {serviceName}: Not Found");
                }
            }

            return result.ToString();
        }
        catch (Exception ex)
        {
            return $"Error checking services: {ex.Message}";
        }
    }

    public string GetDriverBYODStatus()
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("This function is only available on Windows");

        try
        {
            var result = new System.Text.StringBuilder();
            using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_SystemDriver");
            
            result.AppendLine("BYOD drivers status:");
            foreach (ManagementObject driver in searcher.Get())
            {
                var name = driver["Name"]?.ToString();
                var state = driver["State"]?.ToString();
                var startMode = driver["StartMode"]?.ToString();
                
                result.AppendLine($"Driver: {name}");
                result.AppendLine($"  State: {state}");
                result.AppendLine($"  Start Mode: {startMode}");
                result.AppendLine();
            }

            return result.ToString();
        }
        catch (Exception ex)
        {
            return $"Error checking BYOD status: {ex.Message}";
        }
    }

    public string CheckDriverExposedDevices()
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("This function is only available on Windows");

        try
        {
            var result = new System.Text.StringBuilder();
            using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_PnPEntity");
            
            result.AppendLine("Connected devices:");
            foreach (ManagementObject device in searcher.Get())
            {
                var name = device["Name"]?.ToString();
                var deviceId = device["DeviceID"]?.ToString();
                var status = device["Status"]?.ToString();
                
                result.AppendLine($"Device: {name}");
                result.AppendLine($"  ID: {deviceId}");
                result.AppendLine($"  Status: {status}");
                result.AppendLine();
            }

            return result.ToString();
        }
        catch (Exception ex)
        {
            return $"Error checking devices: {ex.Message}";
        }
    }

    public string CheckWFPStatus()
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("This function is only available on Windows");

        try
        {
            var result = new System.Text.StringBuilder();
            
            using (var service = new ServiceController("mpssvc"))
            {
                result.AppendLine($"Windows Firewall: {GetServiceStatus(service)}");
            }

            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = "advfirewall show allprofiles",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                }
            };

            process.Start();
            string output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();

            result.AppendLine("\nFirewall profiles status:");
            result.AppendLine(output);

            return result.ToString();
        }
        catch (Exception ex)
        {
            return $"Error checking WFP status: {ex.Message}";
        }
    }

    private string GetServiceStatus(ServiceController service)
    {
        try
        {
            switch (service.Status)
            {
                case ServiceControllerStatus.Running:
                    return "Running";
                case ServiceControllerStatus.Stopped:
                    return "Stopped";
                case ServiceControllerStatus.Paused:
                    return "Paused";
                case ServiceControllerStatus.StartPending:
                    return "Starting";
                case ServiceControllerStatus.StopPending:
                    return "Stopping";
                default:
                    return $"Unknown status: {service.Status}";
            }
        }
        catch
        {
            return "Not available";
        }
    }

    public async Task CheckDriversAgainstLolDriversDb()
    {
        var lolDriversService = new LolDriversService();
        Console.WriteLine("Getting vulnerable drivers data...");
        var vulnerableDrivers = await lolDriversService.GetVulnerableDriversAsync();
        
        if (!vulnerableDrivers.Any())
        {
            return;
        }

        Console.WriteLine("Scanning system drivers...");
        var systemDrivers = lolDriversService.GetSystemDrivers();
        
        Console.WriteLine("Checking for vulnerabilities...");
        var vulnerableFound = new HashSet<(string Path, string Name, string Hash, LolDriver VulnInfo)>(
            new VulnerableDriverComparer());

        foreach (var driverPath in systemDrivers)
        {
            try
            {
                var driverName = Path.GetFileName(driverPath);
                using var sha256 = SHA256.Create();
                using var stream = File.OpenRead(driverPath);
                var hash = BitConverter.ToString(sha256.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();

                foreach (var vulnDriver in vulnerableDrivers)
                {
                    if ((vulnDriver.Tags.Any() && driverName.ToLower() == vulnDriver.Tags[0].ToLower()) || 
                        vulnDriver.GetKnownVulnerableSamples().Contains(hash, StringComparer.OrdinalIgnoreCase))
                    {
                        vulnerableFound.Add((driverPath, driverName, hash, vulnDriver));
                        break;
                    }
                }
            }
            catch (Exception) { continue; }
        }

        if (vulnerableFound.Any())
        {
            Console.WriteLine("\n=== Vulnerable Drivers Found ===");
            foreach (var (path, name, hash, vulnInfo) in vulnerableFound)
            {
                Console.WriteLine($"\nName: {name}");
                Console.WriteLine($"Path: {path}");
                Console.WriteLine($"SHA-256: {hash}");
                Console.WriteLine($"Category: {vulnInfo.Category}");
                if (!string.IsNullOrEmpty(vulnInfo.Commands.Description))
                {
                    Console.WriteLine($"Description: {vulnInfo.Commands.Description}");
                }
                Console.WriteLine("-------------------");
            }
        }
        else
        {
            Console.WriteLine("\nNo vulnerable drivers found.");
        }
    }

    private class VulnerableDriverComparer : IEqualityComparer<(string Path, string Name, string Hash, LolDriver VulnInfo)>
    {
        public bool Equals((string Path, string Name, string Hash, LolDriver VulnInfo) x, 
                          (string Path, string Name, string Hash, LolDriver VulnInfo) y)
        {
            return x.Hash.Equals(y.Hash, StringComparison.OrdinalIgnoreCase);
        }

        public int GetHashCode((string Path, string Name, string Hash, LolDriver VulnInfo) obj)
        {
            return obj.Hash.ToLowerInvariant().GetHashCode();
        }
    }

    public string CheckSpecificDriver(string driverName)
    {
        var lolDriversService = new LolDriversService();
        var systemDrivers = lolDriversService.GetSystemDrivers();
        
        var foundDrivers = systemDrivers
            .Where(d => Path.GetFileName(d).Equals(driverName, StringComparison.OrdinalIgnoreCase))
            .ToList();
        
        if (!foundDrivers.Any())
        {
            return $"Driver '{driverName}' not found in the system.";
        }

        var result = new StringBuilder();
        result.AppendLine($"Found {foundDrivers.Count} instance(s) of driver '{driverName}':");
        
        foreach (var driverPath in foundDrivers)
        {
            result.AppendLine($"\nPath: {driverPath}");
            try
            {
                var fileInfo = new FileInfo(driverPath);
                result.AppendLine($"Size: {fileInfo.Length:N0} bytes");
                result.AppendLine($"Created: {fileInfo.CreationTime}");
                result.AppendLine($"Last modified: {fileInfo.LastWriteTime}");
                
                using var sha256 = SHA256.Create();
                using var stream = File.OpenRead(driverPath);
                var hash = BitConverter.ToString(sha256.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
                result.AppendLine($"SHA-256: {hash}");
            }
            catch (Exception ex)
            {
                result.AppendLine($"Error reading file details: {ex.Message}");
            }
        }
        
        return result.ToString();
    }
}
