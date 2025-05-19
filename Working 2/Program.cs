using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Serilog;
using Serilog.Events;
using Spectre.Console;
using WindowsDriverInfo.Models;
using WindowsDriverInfo.Services;
using Quartz;
using Quartz.Impl;
using System.Security.Principal;

namespace WindowsDriverInfo;

public class Program
{
    static async Task<int> Main(string[] args)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        
        if (!OperatingSystem.IsWindows())
        {
            AnsiConsole.MarkupLine("[red]This program is intended only for Windows.[/]");
            return 1;
        }

        if (!IsAdministrator())
        {
            AnsiConsole.MarkupLine("[red]This program requires administrator privileges. Please run as administrator.[/]");
            return 1;
        }

        try
        {
            // Create necessary directories
            Directory.CreateDirectory("logs");
            Directory.CreateDirectory("reports");
            Directory.CreateDirectory("Templates");

            var services = new ServiceCollection();
            ConfigureServices(services);
            
            using var serviceProvider = services.BuildServiceProvider();
            var logger = serviceProvider.GetRequiredService<ILogger<Program>>();
            var config = serviceProvider.GetRequiredService<DriverCheckerConfig>();
            var provider = serviceProvider.GetRequiredService<DriverInfoProvider>();
            var monitor = serviceProvider.GetRequiredService<DriverMonitor>();
            var reportGenerator = serviceProvider.GetRequiredService<ReportService>();
            var scheduler = serviceProvider.GetRequiredService<SchedulerService>();

            // Start the scheduler
            await scheduler.StartAsync();

            while (true)
            {
                Console.Clear();
                var panel = new Panel(new FigletText("Driver Security")
                    .Centered()
                    .Color(Color.Blue))
                    .Expand()
                    .Border(BoxBorder.Double)
                    .BorderColor(Color.Blue);

                AnsiConsole.Write(panel);

                // Добавляем статистику
                var stats = new Table()
                    .Border(TableBorder.Rounded)
                    .BorderColor(Color.Blue)
                    .AddColumn(new TableColumn("System Status").Centered());

                stats.AddRow("[blue]Last scan:[/] " + (provider.GetLastScanTime()?.ToString("yyyy-MM-dd HH:mm:ss") ?? "Never"));
                stats.AddRow("[blue]Monitored drivers:[/] " + provider.GetAllScannedDrivers().Count);
                stats.AddRow("[blue]Next scheduled scan:[/] " + (scheduler.GetNextScanTime()?.ToString("yyyy-MM-dd HH:mm:ss") ?? "Not scheduled"));

                AnsiConsole.Write(stats);
                AnsiConsole.WriteLine();

                var menu = new SelectionPrompt<string>()
                    .Title("[blue]Select an action:[/]")
                    .PageSize(10)
                    .HighlightStyle(new Style(foreground: Color.Blue))
                    .AddChoiceGroup("Security", new[]
                    {
                        "🔍 Scan system for vulnerable drivers",
                        "📊 Generate driver report"
                    })
                    .AddChoiceGroup("Management", new[]
                    {
                        "⏰ Configure scan schedule",
                        "📝 View recent reports",
                        "⚙️ Settings"
                    })
                    .AddChoiceGroup("System", new[]
                    {
                        "❌ Exit"
                    });

                var choice = AnsiConsole.Prompt(menu);

                // Показываем описание выбранного пункта
                var description = choice switch
                {
                    "🔍 Scan system for vulnerable drivers" => 
                        "Performs a comprehensive scan of all system drivers for security vulnerabilities",
                    "📊 Generate driver report" => 
                        "Creates detailed security report for single driver or all scanned drivers",
                    "⏰ Configure scan schedule" => 
                        "Set up automatic periodic scanning of system drivers",
                    "📝 View recent reports" => 
                        "Browse and open recently generated security reports",
                    "⚙️ Settings" => 
                        "Configure application settings and monitoring options",
                    _ => string.Empty
                };

                if (!string.IsNullOrEmpty(description))
                {
                    AnsiConsole.WriteLine();
                    AnsiConsole.MarkupLine($"[grey]{description}[/]");
                    AnsiConsole.WriteLine();
                }

                try
                {
                    switch (choice)
                    {
                        case "🔍 Scan system for vulnerable drivers":
                            await ScanSystem(provider);
                            break;

                        case "📊 Generate driver report":
                            await GenerateReport(provider, reportGenerator);
                            break;

                        case "⏰ Configure scan schedule":
                            await ConfigureSchedule(scheduler);
                            break;

                        case "📝 View recent reports":
                            ShowRecentReports();
                            break;

                        case "⚙️ Settings":
                            ConfigureSettings(config);
                            break;

                        case "❌ Exit":
                            await scheduler.StopAsync();
                            return 0;
                    }
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Error during operation");
                    AnsiConsole.MarkupLine($"[red]Error: {ex.Message}[/]");
                }

                AnsiConsole.MarkupLine("\n[yellow]Press any key to continue...[/]");
                Console.ReadKey();
            }
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine($"[red]Critical error: {ex.Message}[/]");
            return 1;
        }
    }

    private static bool IsAdministrator()
    {
        var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static void ConfigureServices(IServiceCollection services)
    {
        services.AddLogging(builder =>
        {
            builder.AddConsole();
            builder.AddDebug();
            builder.AddSerilog(new Serilog.LoggerConfiguration()
                .WriteTo.File("logs/app.log", rollingInterval: RollingInterval.Day)
                .WriteTo.Console()
                .CreateLogger());
        });

        services.AddSingleton<DriverCheckerConfig>(new DriverCheckerConfig
        {
            DriversPath = @"C:\Windows\System32\drivers",
            CacheTimeout = TimeSpan.FromMinutes(30),
            EnableRealTimeMonitoring = true,
            ReportOutputPath = "reports"
        });

        services.AddSingleton<DriverInfoProvider>();
        services.AddSingleton<DriverMonitor>();
        services.AddSingleton<ReportService>();
        services.AddSingleton<DriverAnalyzer>();
        services.AddSingleton<MicrosoftSecurityService>();
        services.AddSingleton<IScheduler>(sp => 
        {
            var factory = new StdSchedulerFactory();
            return factory.GetScheduler().Result;
        });
        services.AddSingleton<SchedulerService>();
    }

    private static async Task ScanSystem(DriverInfoProvider provider)
    {
        AnsiConsole.Progress()
            .Start(ctx =>
            {
                var task = ctx.AddTask("[green]Scanning system...[/]");
                task.StartTask();
                
                provider.CheckDriversAgainstLolDriversDb().Wait();
                
                task.StopTask();
            });

        AnsiConsole.MarkupLine("[green]Scan completed![/]");
    }

    private static async Task GenerateReport(DriverInfoProvider provider, ReportService reportGenerator)
    {
        var reportType = new SelectionPrompt<string>()
            .Title("[yellow]Select report type:[/]")
            .AddChoices(new[]
            {
                "📄 Generate report for single driver",
                "📊 Generate report for all scanned drivers",
                "❌ Cancel"
            });

        var choice = AnsiConsole.Prompt(reportType);

        switch (choice)
        {
            case "📄 Generate report for single driver":
                var path = AnsiConsole.Ask<string>("Enter driver path: ");
                var report = new DriverSecurityReport
                {
                    DriverName = Path.GetFileName(path),
                    DriverPath = path,
                    DriverVersion = provider.GetDriverVersion(path),
                    Publisher = provider.GetDriverPublisher(path),
                    SignatureStatus = provider.CheckDriverSignature(path) ? SecurityStatus.Safe : SecurityStatus.Danger,
                    LolDriversStatus = provider.CheckLolDrivers(path) ? SecurityStatus.Safe : SecurityStatus.Danger,
                    OverallStatus = provider.GetOverallSecurityStatus(path),
                    SignatureVerification = provider.GetSignatureVerificationDetails(path),
                    LolDriversAnalysis = provider.GetLolDriversAnalysis(path),
                    Recommendations = provider.GetSecurityRecommendations(path),
                    LastScan = DateTime.Now,
                    ScanDuration = TimeSpan.FromSeconds(1)
                };

                await reportGenerator.GenerateReportAsync(report);
                AnsiConsole.MarkupLine("[green]Report generated successfully![/]");
                break;

            case "📊 Generate report for all scanned drivers":
                var drivers = provider.GetAllScannedDrivers();
                if (!drivers.Any())
                {
                    AnsiConsole.MarkupLine("[yellow]No scanned drivers found. Please scan the system first.[/]");
                    return;
                }

                var reports = new List<DriverSecurityReport>();
                foreach (var driver in drivers)
                {
                    var driverReport = new DriverSecurityReport
                    {
                        DriverName = Path.GetFileName(driver),
                        DriverPath = driver,
                        DriverVersion = provider.GetDriverVersion(driver),
                        Publisher = provider.GetDriverPublisher(driver),
                        SignatureStatus = provider.CheckDriverSignature(driver) ? SecurityStatus.Safe : SecurityStatus.Danger,
                        LolDriversStatus = provider.CheckLolDrivers(driver) ? SecurityStatus.Safe : SecurityStatus.Danger,
                        OverallStatus = provider.GetOverallSecurityStatus(driver),
                        SignatureVerification = provider.GetSignatureVerificationDetails(driver),
                        LolDriversAnalysis = provider.GetLolDriversAnalysis(driver),
                        Recommendations = provider.GetSecurityRecommendations(driver),
                        LastScan = DateTime.Now,
                        ScanDuration = TimeSpan.FromSeconds(1)
                    };
                    reports.Add(driverReport);
                }

                await reportGenerator.GenerateReportAsync(reports);
                AnsiConsole.MarkupLine("[green]Report generated successfully![/]");
                break;
        }
    }

    private static async Task ConfigureSchedule(SchedulerService scheduler)
    {
        var schedule = new SelectionPrompt<string>()
            .Title("[yellow]Select schedule:[/]")
            .AddChoices(new[]
            {
                "Daily at 3:00 AM",
                "Weekly on Monday at 3:00 AM",
                "Monthly on the 1st at 3:00 AM",
                "Cancel schedule"
            });

        var choice = AnsiConsole.Prompt(schedule);
        string cronExpression = choice switch
        {
            "Daily at 3:00 AM" => "0 0 3 * * ?",
            "Weekly on Monday at 3:00 AM" => "0 0 3 ? * MON",
            "Monthly on the 1st at 3:00 AM" => "0 0 3 1 * ?",
            _ => null
        };

        if (cronExpression != null)
        {
            await scheduler.ScheduleScanAsync(cronExpression);
            AnsiConsole.MarkupLine("[green]Schedule configured successfully![/]");
        }
        else
        {
            await scheduler.RemoveScheduleAsync();
            AnsiConsole.MarkupLine("[yellow]Schedule cancelled.[/]");
        }
    }

    private static void ShowRecentReports()
    {
        var reportsDir = "reports";
        if (!Directory.Exists(reportsDir))
        {
            AnsiConsole.MarkupLine("[yellow]No reports found.[/]");
            return;
        }

        var reports = Directory.GetFiles(reportsDir, "report_*.html")
            .OrderByDescending(f => f)
            .Take(5)
            .ToList();

        if (!reports.Any())
        {
            AnsiConsole.MarkupLine("[yellow]No reports found.[/]");
            return;
        }

        var table = new Table();
        table.AddColumn("Date");
        table.AddColumn("Actions");

        foreach (var report in reports)
        {
            var fileName = Path.GetFileName(report);
            var date = fileName.Split('_')[1];
            table.AddRow(
                date,
                $"[blue]Open[/]"
            );
        }

        AnsiConsole.Write(table);
    }

    private static void ConfigureSettings(DriverCheckerConfig config)
    {
        var settings = new SelectionPrompt<string>()
            .Title("[yellow]Settings:[/]")
            .AddChoices(new[]
            {
                "Change drivers path",
                "Configure cache timeout",
                "Toggle real-time monitoring",
                "Back to main menu"
            });

        var choice = AnsiConsole.Prompt(settings);
        switch (choice)
        {
            case "Change drivers path":
                config.DriversPath = AnsiConsole.Prompt(
                    new TextPrompt<string>("[yellow]Enter new path:[/]"));
                break;

            case "Configure cache timeout":
                var minutes = AnsiConsole.Prompt(
                    new TextPrompt<int>("[yellow]Enter timeout in minutes:[/]")
                        .Validate(m => m > 0, "Timeout must be greater than 0"));
                config.CacheTimeout = TimeSpan.FromMinutes(minutes);
                break;

            case "Toggle real-time monitoring":
                config.EnableRealTimeMonitoring = !config.EnableRealTimeMonitoring;
                AnsiConsole.MarkupLine($"[green]Real-time monitoring {(config.EnableRealTimeMonitoring ? "enabled" : "disabled")}[/]");
                break;
        }
    }
}
