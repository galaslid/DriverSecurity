using System.Management;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using WindowsDriverInfo.Models;

namespace WindowsDriverInfo.Services;

public class MicrosoftSecurityService
{
    private readonly ILogger<MicrosoftSecurityService> _logger;

    public MicrosoftSecurityService(ILogger<MicrosoftSecurityService> logger)
    {
        _logger = logger;
    }

    public async Task<DriverSecurityStatus> CheckDriverSecurityAsync(string driverPath)
    {
        try
        {
            var wdacStatus = await CheckWDACStatusAsync(driverPath);
            var signatureStatus = await CheckSignatureStatusAsync(driverPath);
            var defenderStatus = await CheckDefenderStatusAsync(driverPath);

            return new DriverSecurityStatus
            {
                WDACStatus = wdacStatus,
                SignatureStatus = signatureStatus,
                DefenderStatus = defenderStatus,
                IsSecure = wdacStatus.IsAllowed && 
                          signatureStatus.IsValid && 
                          defenderStatus.IsClean
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking Microsoft security status for driver: {DriverPath}", driverPath);
            throw;
        }
    }

    public async Task<WDACStatus> CheckWDACStatusAsync(string driverPath)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher("root\\CIMV2", 
                "SELECT * FROM Win32_CodecFile WHERE Path = '" + driverPath + "'");
            using var collection = searcher.Get();
            
            var status = new WDACStatus
            {
                IsAllowed = true,
                PolicyDetails = "No WDAC policy found"
            };

            foreach (var policy in collection)
            {
                var policyStatus = policy.GetPropertyValue("Status")?.ToString();
                if (policyStatus == "Enabled")
                {
                    status.IsAllowed = false;
                    status.PolicyDetails = "WDAC policy is enabled";
                    break;
                }
            }

            return status;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking WDAC status");
            return new WDACStatus
            {
                IsAllowed = true,
                PolicyDetails = "Error checking WDAC status"
            };
        }
    }

    public async Task<SignatureStatus> CheckSignatureStatusAsync(string driverPath)
    {
        try
        {
            var status = new SignatureStatus
            {
                IsValid = false,
                Publisher = "Unknown",
                Issuer = "Unknown"
            };

            using var searcher = new ManagementObjectSearcher("root\\CIMV2", 
                "SELECT * FROM Win32_CodecFile WHERE Path = '" + driverPath + "'");
            using var collection = searcher.Get();

            foreach (var file in collection)
            {
                var manufacturer = file.GetPropertyValue("Manufacturer")?.ToString();
                var company = file.GetPropertyValue("Company")?.ToString();
                
                status.IsValid = true;
                status.Publisher = manufacturer ?? company ?? "Unknown";
                status.Issuer = "Microsoft";
                break;
            }

            return status;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking signature status");
            return new SignatureStatus
            {
                IsValid = false,
                Publisher = "Error",
                Issuer = "Error"
            };
        }
    }

    public async Task<DefenderStatus> CheckDefenderStatusAsync(string driverPath)
    {
        try
        {
            var status = new DefenderStatus
            {
                IsClean = true,
                ThreatLevel = "Unknown",
                LastScanTime = DateTime.Now
            };

            using var searcher = new ManagementObjectSearcher("root\\CIMV2", 
                "SELECT * FROM Win32_CodecFile WHERE Path = '" + driverPath + "'");
            using var collection = searcher.Get();

            foreach (var threat in collection)
            {
                var threatLevel = threat.GetPropertyValue("ThreatLevel")?.ToString();
                var lastScanTime = threat.GetPropertyValue("LastScanTime")?.ToString();
                
                status.IsClean = false;
                status.ThreatLevel = threatLevel ?? "Unknown";
                if (DateTime.TryParse(lastScanTime, out DateTime scanTime))
                {
                    status.LastScanTime = scanTime;
                }
                break;
            }

            return status;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking Defender status");
            return new DefenderStatus
            {
                IsClean = true,
                ThreatLevel = "Error",
                LastScanTime = DateTime.Now
            };
        }
    }
}
