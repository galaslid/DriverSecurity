using Quartz;
using Microsoft.Extensions.Logging;

namespace WindowsDriverInfo.Services;

public class SchedulerService
{
    private readonly IScheduler _scheduler;
    private readonly ILogger<SchedulerService> _logger;

    public SchedulerService(IScheduler scheduler, ILogger<SchedulerService> logger)
    {
        _scheduler = scheduler;
        _logger = logger;
    }

    public async Task StartAsync()
    {
        await _scheduler.Start();
        _logger.LogInformation("Scheduler started");
    }

    public async Task StopAsync()
    {
        await _scheduler.Shutdown();
        _logger.LogInformation("Scheduler stopped");
    }

    public async Task ScheduleScanAsync(string cronExpression)
    {
        try
        {
            // Сначала удаляем существующее расписание
            await RemoveScheduleAsync();

            var job = JobBuilder.Create<DriverScanJob>()
                .WithIdentity("driverScan", "group1")
                .Build();

            var trigger = TriggerBuilder.Create()
                .WithIdentity("driverScanTrigger", "group1")
                .WithCronSchedule(cronExpression)
                .Build();

            await _scheduler.ScheduleJob(job, trigger);
            _logger.LogInformation("Scheduled driver scan with cron expression: {Expression}", cronExpression);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error scheduling driver scan");
            throw;
        }
    }

    public async Task RemoveScheduleAsync()
    {
        try
        {
            await _scheduler.DeleteJob(new JobKey("driverScan", "group1"));
            _logger.LogInformation("Removed scheduled driver scan");
        }
        catch
        {
            // Игнорируем ошибку, если задание не существует
        }
    }

    public DateTime? GetNextScanTime()
    {
        try
        {
            var trigger = _scheduler.GetTrigger(new TriggerKey("driverScanTrigger", "group1")).Result;
            return trigger?.GetNextFireTimeUtc()?.LocalDateTime;
        }
        catch
        {
            return null;
        }
    }
}

public class DriverScanJob : IJob
{
    private readonly DriverInfoProvider _driverInfoProvider;
    private readonly ILogger<DriverScanJob> _logger;

    public DriverScanJob(DriverInfoProvider driverInfoProvider, ILogger<DriverScanJob> logger)
    {
        _driverInfoProvider = driverInfoProvider;
        _logger = logger;
    }

    public async Task Execute(IJobExecutionContext context)
    {
        _logger.LogInformation("Starting scheduled driver scan");
        await _driverInfoProvider.CheckDriversAgainstLolDriversDb();
        _logger.LogInformation("Completed scheduled driver scan");
    }
} 