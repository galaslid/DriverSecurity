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
using Microsoft.Extensions.Logging;
using WindowsDriverInfo.Exceptions;

namespace WindowsDriverInfo;

public class DriverInfoProvider
{
    private readonly DriverCheckCache _cache;
    private readonly ILogger<DriverInfoProvider> _logger;
    private readonly DriverAnalyzer _analyzer;
    private readonly MicrosoftSecurityService _securityService;

    public DriverInfoProvider(
        ILogger<DriverInfoProvider> logger, 
        ILoggerFactory loggerFactory,
        MicrosoftSecurityService securityService)
    {
        _cache = new DriverCheckCache(TimeSpan.FromMinutes(30));
        _logger = logger;
        _analyzer = new DriverAnalyzer(loggerFactory);
        _securityService = securityService;
    }

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
            Console.WriteLine("\nFound vulnerable drivers:");
            foreach (var (path, name, hash, vulnInfo) in vulnerableFound)
            {
                Console.WriteLine($"\nDriver: {name}");
                Console.WriteLine($"Path: {path}");
                Console.WriteLine($"Hash: {hash}");
                Console.WriteLine($"Vulnerability: {vulnInfo.Description}");
            }
        }
        else
        {
            Console.WriteLine("\nNo vulnerable drivers found.");
        }
    }

    public string CheckSpecificDriver(string driverName)
    {
        try
        {
            var systemDrivers = new LolDriversService().GetSystemDrivers();
            var driverPath = systemDrivers.FirstOrDefault(d => 
                Path.GetFileName(d).Equals(driverName, StringComparison.OrdinalIgnoreCase));

            if (driverPath == null)
            {
                return $"Driver {driverName} not found in system.";
            }

            using var sha256 = SHA256.Create();
            using var stream = File.OpenRead(driverPath);
            var hash = BitConverter.ToString(sha256.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();

            var lolDriversService = new LolDriversService();
            var vulnerableDrivers = lolDriversService.GetVulnerableDriversAsync().GetAwaiter().GetResult();

            foreach (var vulnDriver in vulnerableDrivers)
            {
                if ((vulnDriver.Tags.Any() && driverName.ToLower() == vulnDriver.Tags[0].ToLower()) || 
                    vulnDriver.GetKnownVulnerableSamples().Contains(hash, StringComparer.OrdinalIgnoreCase))
                {
                    return $"Driver {driverName} is vulnerable!\nVulnerability: {vulnDriver.Description}";
                }
            }

            return $"Driver {driverName} appears to be safe.";
        }
        catch (Exception ex)
        {
            return $"Error checking driver: {ex.Message}";
        }
    }

    public async Task<DriverSecurityReport> GetComprehensiveDriverCheckAsync(string driverPath)
    {
        try
        {
            var lolDriversService = new LolDriversService();
            var vulnerableDrivers = await lolDriversService.GetVulnerableDriversAsync();
            var driverName = Path.GetFileName(driverPath);
            var hash = await CalculateDriverHashAsync(driverPath);
            
            var lolDriversResult = new LolDriversCheckResult
            {
                IsVulnerable = false,
                VulnerabilityDetails = null
            };

            foreach (var vulnDriver in vulnerableDrivers)
            {
                if ((vulnDriver.Tags.Any() && driverName.ToLower() == vulnDriver.Tags[0].ToLower()) || 
                    vulnDriver.GetKnownVulnerableSamples().Contains(hash, StringComparer.OrdinalIgnoreCase))
                {
                    lolDriversResult = new LolDriversCheckResult
                    {
                        IsVulnerable = true,
                        VulnerabilityDetails = vulnDriver
                    };
                    break;
                }
            }

            var microsoftSecurityResult = await _securityService.CheckDriverSecurityAsync(driverPath);
            var analysisResult = await _analyzer.AnalyzeDriverAsync(driverPath);

            return new DriverSecurityReport
            {
                DriverName = driverName,
                Path = driverPath,
                Hash = hash,
                LolDriversCheck = lolDriversResult,
                MicrosoftSecurityCheck = microsoftSecurityResult,
                DriverAnalysis = analysisResult,
                OverallSecurityStatus = DetermineOverallStatus(lolDriversResult, microsoftSecurityResult)
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error performing comprehensive driver check: {DriverPath}", driverPath);
            throw;
        }
    }

    private async Task<string> CalculateDriverHashAsync(string driverPath)
    {
        using var sha256 = SHA256.Create();
        using var stream = File.OpenRead(driverPath);
        return BitConverter.ToString(sha256.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
    }

    private SecurityStatus DetermineOverallStatus(
        LolDriversCheckResult lolDriversResult, 
        DriverSecurityStatus microsoftSecurityResult)
    {
        if (lolDriversResult.IsVulnerable)
            return SecurityStatus.Critical;

        if (!microsoftSecurityResult.IsSecure)
            return SecurityStatus.Warning;

        return SecurityStatus.Secure;
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
}
