using System.Text.Json;
using Microsoft.Extensions.Logging;
using WindowsDriverInfo.Models;

namespace WindowsDriverInfo.Services;

public class ReportGenerator
{
    private readonly ILogger<ReportGenerator> _logger;

    public ReportGenerator(ILogger<ReportGenerator> logger)
    {
        _logger = logger;
    }

    public async Task<string> GenerateReportAsync(List<DriverReport> reports)
    {
        try
        {
            var template = await File.ReadAllTextAsync("report_template.html");
            var json = JsonSerializer.Serialize(reports);
            return template.Replace("{{data}}", json);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error generating report");
            throw;
        }
    }
}
