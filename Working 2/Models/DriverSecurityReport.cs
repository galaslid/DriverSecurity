using System;
using WindowsDriverInfo.Services;

namespace WindowsDriverInfo.Models;

public enum SecurityStatus
{
    Safe,
    Warning,
    Danger,
    Critical,
    Secure
}

public class DriverSecurityReport
{
    public string DriverName { get; set; } = string.Empty;
    public string DriverPath { get; set; } = string.Empty;
    public string DriverVersion { get; set; } = string.Empty;
    public string Publisher { get; set; } = string.Empty;
    
    public SecurityStatus SignatureStatus { get; set; }
    public SecurityStatus LolDriversStatus { get; set; }
    public SecurityStatus OverallStatus { get; set; }
    
    public string SignatureVerification { get; set; } = string.Empty;
    public string LolDriversAnalysis { get; set; } = string.Empty;
    public string Recommendations { get; set; } = string.Empty;
    
    public DateTime LastScan { get; set; }
    public TimeSpan ScanDuration { get; set; }
}

public class LolDriversCheckResult
{
    public bool IsVulnerable { get; set; }
    public LolDriver VulnerabilityDetails { get; set; }
}

public class DriverSecurityBatchReport
{
    public List<DriverSecurityReport> Reports { get; set; } = new();
    public DateTime GeneratedAt { get; set; } = DateTime.Now;
    public int TotalDrivers => Reports.Count;
    public int CriticalDrivers => Reports.Count(r => r.OverallStatus == SecurityStatus.Critical);
    public int WarningDrivers => Reports.Count(r => r.OverallStatus == SecurityStatus.Warning);
    public int SafeDrivers => Reports.Count(r => r.OverallStatus == SecurityStatus.Safe);
}
