using WindowsDriverInfo.Services;

namespace WindowsDriverInfo.Models;

public class DriverSecurityReport
{
    public string DriverName { get; set; }
    public string Path { get; set; }
    public string Hash { get; set; }
    public LolDriversCheckResult LolDriversCheck { get; set; }
    public DriverSecurityStatus MicrosoftSecurityCheck { get; set; }
    public DriverAnalyzer.DriverAnalysisResult DriverAnalysis { get; set; }
    public SecurityStatus OverallSecurityStatus { get; set; }
}

public class LolDriversCheckResult
{
    public bool IsVulnerable { get; set; }
    public LolDriver VulnerabilityDetails { get; set; }
}

public enum SecurityStatus
{
    Secure,
    Warning,
    Critical
}
