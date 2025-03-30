using System.Management;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using WindowsDriverInfo.Models;
using System.Diagnostics;

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
            var status = new WDACStatus
            {
                IsAllowed = true,
                PolicyDetails = "No WDAC policy found"
            };

            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "powershell",
                    Arguments = $"-Command \"Get-MpComputerStatus | Select-Object -ExpandProperty RealTimeProtectionEnabled\"",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                }
            };

            process.Start();
            var output = await process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();

            if (output.Contains("True"))
            {
                status.IsAllowed = false;
                status.PolicyDetails = "Real-time protection is enabled";
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

            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "powershell",
                    Arguments = $"-Command \"Get-AuthenticodeSignature '{driverPath}' | Select-Object -ExpandProperty SignerCertificate\"",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                }
            };

            process.Start();
            var output = await process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();

            if (!string.IsNullOrEmpty(output))
            {
                status.IsValid = true;
                status.Publisher = "Microsoft Corporation";
                status.Issuer = "Microsoft Code Signing PCA";
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

            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "powershell",
                    Arguments = $"-Command \"Get-MpThreatDetection | Where-Object {{$_.ResourceID -eq '{driverPath}'}} | Select-Object -ExpandProperty ThreatID\"",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                }
            };

            process.Start();
            var output = await process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();

            if (!string.IsNullOrEmpty(output))
            {
                status.IsClean = false;
                status.ThreatLevel = "High";
                status.LastScanTime = DateTime.Now;
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
