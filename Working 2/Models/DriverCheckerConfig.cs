namespace WindowsDriverInfo.Models;

public class DriverCheckerConfig
{
    public string DriversPath { get; set; } = @"C:\Windows\System32\drivers";
    public TimeSpan CacheTimeout { get; set; } = TimeSpan.FromMinutes(30);
    public bool EnableRealTimeMonitoring { get; set; } = true;
    public string ReportOutputPath { get; set; } = "reports";
}
