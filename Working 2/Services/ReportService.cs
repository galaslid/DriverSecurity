using RazorLight;
using WindowsDriverInfo.Models;
using Microsoft.Extensions.Logging;

namespace WindowsDriverInfo.Services;

public class ReportService
{
    private readonly ILogger<ReportService> _logger;
    private readonly string _reportPath;
    private const int MaxHistoryReports = 5;

    public ReportService(ILogger<ReportService> logger, string reportPath = "reports")
    {
        _logger = logger;
        _reportPath = reportPath;
        Directory.CreateDirectory(reportPath);
    }

    public async Task GenerateReportAsync(List<DriverSecurityReport> reports)
    {
        var batchReport = new DriverSecurityBatchReport
        {
            Reports = reports,
            GeneratedAt = DateTime.Now
        };

        await GenerateHtmlReportAsync(batchReport);
        await CleanupOldReportsAsync();
    }

    public async Task GenerateReportAsync(DriverSecurityReport report)
    {
        await GenerateReportAsync(new List<DriverSecurityReport> { report });
    }

    private async Task GenerateHtmlReportAsync(DriverSecurityBatchReport report)
    {
        var engine = new RazorLightEngineBuilder()
            .UseFileSystemProject(Directory.GetCurrentDirectory())
            .UseMemoryCachingProvider()
            .Build();

        var template = await engine.CompileTemplateAsync("Templates/Report.cshtml");
        var result = await engine.RenderTemplateAsync(template, report);

        var fileName = $"report_{DateTime.Now:yyyyMMdd_HHmmss}.html";
        var filePath = Path.Combine(_reportPath, fileName);
        await File.WriteAllTextAsync(filePath, result);

        _logger.LogInformation("Generated HTML report: {FilePath}", filePath);
    }

    private async Task CleanupOldReportsAsync()
    {
        var files = Directory.GetFiles(_reportPath)
            .OrderByDescending(f => f)
            .Skip(MaxHistoryReports);

        foreach (var file in files)
        {
            try
            {
                File.Delete(file);
                _logger.LogInformation("Deleted old report: {FilePath}", file);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting old report: {FilePath}", file);
            }
        }
    }
} 