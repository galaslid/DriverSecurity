using System.Security.Cryptography.X509Certificates;
using System.Diagnostics;
using Microsoft.Win32;
using Microsoft.Extensions.Logging;
using WindowsDriverInfo.Exceptions;

namespace WindowsDriverInfo.Services;

public class DriverAnalyzer
{
    private readonly ILogger<DriverAnalyzer> _logger;

    public DriverAnalyzer(ILoggerFactory loggerFactory)
    {
        _logger = loggerFactory.CreateLogger<DriverAnalyzer>();
    }

    public class DriverAnalysisResult
    {
        public string DriverName { get; set; }
        public string Version { get; set; }
        public string Publisher { get; set; }
        public bool IsSigned { get; set; }
        public string SignatureStatus { get; set; }
        public DateTime LastModified { get; set; }
        public string FileSize { get; set; }
        public List<string> Dependencies { get; set; }
        public string SecurityStatus { get; set; }
    }

    public async Task<DriverAnalysisResult> AnalyzeDriverAsync(string driverPath)
    {
        try
        {
            var result = new DriverAnalysisResult
            {
                DriverName = Path.GetFileName(driverPath),
                LastModified = File.GetLastWriteTime(driverPath),
                FileSize = FormatFileSize(new FileInfo(driverPath).Length),
                Dependencies = new List<string>()
            };

            // Получаем информацию о версии
            var versionInfo = FileVersionInfo.GetVersionInfo(driverPath);
            result.Version = versionInfo.FileVersion ?? "Unknown";
            result.Publisher = versionInfo.CompanyName ?? "Unknown";

            // Проверяем подпись
            var signatureInfo = await CheckDigitalSignatureAsync(driverPath);
            result.IsSigned = signatureInfo.IsSigned;
            result.SignatureStatus = signatureInfo.Status;

            // Получаем зависимости
            result.Dependencies = await GetDriverDependenciesAsync(driverPath);

            // Проверяем безопасность
            result.SecurityStatus = await CheckSecurityStatusAsync(driverPath);

            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error analyzing driver: {DriverPath}", driverPath);
            throw new DriverCheckException($"Failed to analyze driver: {ex.Message}", driverPath);
        }
    }

    private async Task<(bool IsSigned, string Status)> CheckDigitalSignatureAsync(string filePath)
    {
        try
        {
            var certificate = new X509Certificate2(filePath);
            return (true, "Valid");
        }
        catch
        {
            return (false, "Not signed");
        }
    }

    private async Task<List<string>> GetDriverDependenciesAsync(string driverPath)
    {
        var dependencies = new List<string>();
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            if (key != null)
            {
                var driverName = Path.GetFileNameWithoutExtension(driverPath);
                var serviceKey = key.OpenSubKey(driverName);
                if (serviceKey != null)
                {
                    var dependsOn = serviceKey.GetValue("DependOnService") as string[];
                    if (dependsOn != null)
                    {
                        dependencies.AddRange(dependsOn);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to get dependencies for driver: {DriverPath}", driverPath);
        }
        return dependencies;
    }

    private async Task<string> CheckSecurityStatusAsync(string driverPath)
    {
        try
        {
            var fileInfo = new FileInfo(driverPath);
            var acl = fileInfo.GetAccessControl();
            
            // Проверяем права доступа
            var hasRestrictedAccess = acl.GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier))
                .Cast<System.Security.AccessControl.FileSystemAccessRule>()
                .Any(rule => rule.AccessControlType == System.Security.AccessControl.AccessControlType.Deny);

            return hasRestrictedAccess ? "Restricted" : "Normal";
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to check security status for driver: {DriverPath}", driverPath);
            return "Unknown";
        }
    }

    private string FormatFileSize(long bytes)
    {
        string[] sizes = { "B", "KB", "MB", "GB" };
        int order = 0;
        double size = bytes;
        while (size >= 1024 && order < sizes.Length - 1)
        {
            order++;
            size /= 1024;
        }
        return $"{size:0.##} {sizes[order]}";
    }
}
