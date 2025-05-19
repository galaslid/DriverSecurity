namespace WindowsDriverInfo.Models;

public class DriverReport
{
    public string DriverName { get; set; }
    public string Path { get; set; }
    public string Hash { get; set; }
    public bool IsVulnerable { get; set; }
    public string VulnerabilityType { get; set; }
    public DateTime CheckTime { get; set; }
    public string SystemInfo { get; set; }
}
