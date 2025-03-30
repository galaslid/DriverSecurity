namespace WindowsDriverInfo.Models;

public class DriverSecurityStatus
{
    public WDACStatus WDACStatus { get; set; }
    public SignatureStatus SignatureStatus { get; set; }
    public DefenderStatus DefenderStatus { get; set; }
    public bool IsSecure { get; set; }
}

public class WDACStatus
{
    public bool IsAllowed { get; set; }
    public string PolicyDetails { get; set; }
}

public class SignatureStatus
{
    public bool IsValid { get; set; }
    public string Publisher { get; set; }
    public string Issuer { get; set; }
}

public class DefenderStatus
{
    public bool IsClean { get; set; }
    public string ThreatLevel { get; set; }
    public DateTime LastScanTime { get; set; }
}
