using System.IO;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using WindowsDriverInfo.Models;

namespace WindowsDriverInfo.Services;

public class DriverMonitor : IDisposable, IHostedService
{
    private readonly FileSystemWatcher _watcher;
    private readonly DriverInfoProvider _provider;
    private readonly ILogger<DriverMonitor> _logger;
    private readonly VulnerableDriverVersionService _vulnerableVersionService;
    private readonly TimeSpan _updateInterval = TimeSpan.FromHours(24);

    public DriverMonitor(DriverInfoProvider provider, DriverCheckerConfig config, ILogger<DriverMonitor> logger, VulnerableDriverVersionService vulnerableVersionService)
    {
        _provider = provider;
        _logger = logger;
        _vulnerableVersionService = vulnerableVersionService;
        
        _watcher = new FileSystemWatcher(config.DriversPath)
        {
            NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite,
            Filter = "*.sys",
            EnableRaisingEvents = config.EnableRealTimeMonitoring
        };

        _watcher.Created += OnDriverCreated;
        _watcher.Changed += OnDriverChanged;
    }

    private async void OnDriverCreated(object sender, FileSystemEventArgs e)
    {
        try
        {
            _logger.LogInformation("New driver detected: {DriverPath}", e.FullPath);
            await CheckDriver(e.FullPath);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking new driver: {DriverPath}", e.FullPath);
        }
    }

    private async void OnDriverChanged(object sender, FileSystemEventArgs e)
    {
        try
        {
            _logger.LogInformation("Driver modified: {DriverPath}", e.FullPath);
            await CheckDriver(e.FullPath);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking modified driver: {DriverPath}", e.FullPath);
        }
    }

    private async Task CheckDriver(string driverPath)
    {
        try
        {
            var report = await _provider.GetComprehensiveDriverCheckAsync(driverPath);
            _logger.LogInformation("Driver {DriverPath} vulnerability status: {IsVulnerable}", 
                driverPath, report.LolDriversCheck.IsVulnerable);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking driver: {DriverPath}", driverPath);
        }
    }

    public void Dispose()
    {
        _watcher?.Dispose();
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        // Запускаем мониторинг файлов
        _watcher.EnableRaisingEvents = true;
        
        // Запускаем обновление базы данных
        _ = ExecuteAsync(cancellationToken);
        
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        return Task.CompletedTask;
    }

    private async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            await _vulnerableVersionService.UpdateVulnerableVersionsDatabaseAsync();
            await Task.Delay(_updateInterval, stoppingToken);
        }
    }
}
