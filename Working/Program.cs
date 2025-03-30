using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using WindowsDriverInfo.Models;
using WindowsDriverInfo.Services;

namespace WindowsDriverInfo;

public class Program
{
    static async Task Main(string[] args)
    {
        if (!OperatingSystem.IsWindows())
        {
            Console.WriteLine("This program is intended only for Windows.");
            return;
        }

        var services = new ServiceCollection();
        ConfigureServices(services);
        
        using var serviceProvider = services.BuildServiceProvider();
        var logger = serviceProvider.GetRequiredService<ILogger<Program>>();
        var config = serviceProvider.GetRequiredService<DriverCheckerConfig>();
        var provider = serviceProvider.GetRequiredService<DriverInfoProvider>();
        var monitor = serviceProvider.GetRequiredService<DriverMonitor>();
        var reportGenerator = serviceProvider.GetRequiredService<ReportGenerator>();

        bool exit = false;

        while (!exit)
        {
            Console.Clear();
            Console.WriteLine("=== Windows Driver Check Menu ===");
            Console.WriteLine("1. Check Driver Signature Status");
            Console.WriteLine("2. Check Driver BYOD Status");
            Console.WriteLine("3. Check Driver Services");
            Console.WriteLine("4. Check for Vulnerable Drivers");
            Console.WriteLine("5. Check Specific Driver");
            Console.WriteLine("6. Comprehensive Driver Security Check");
            Console.WriteLine("0. Exit");

            if (int.TryParse(Console.ReadLine(), out int choice))
            {
                Console.Clear();
                try
                {
                    switch (choice)
                    {
                        case 1:
                            Console.WriteLine($"Driver signature status: {provider.CheckDriverSignatureEnforcement()}");
                            break;
                        case 2:
                            Console.WriteLine(provider.GetDriverBYODStatus());
                            break;
                        case 3:
                            Console.WriteLine(provider.CheckDriverServices());
                            break;
                        case 4:
                            await provider.CheckDriversAgainstLolDriversDb();
                            break;
                        case 5:
                            Console.Write("Enter driver name: ");
                            var driverName = Console.ReadLine();
                            if (string.IsNullOrWhiteSpace(driverName))
                            {
                                Console.WriteLine("Invalid driver name!");
                                break;
                            }
                            Console.WriteLine(provider.CheckSpecificDriver(driverName));
                            break;
                        case 6:
                            Console.Write("Enter driver path: ");
                            var driverPath = Console.ReadLine();
                            if (string.IsNullOrWhiteSpace(driverPath))
                            {
                                Console.WriteLine("Invalid driver path!");
                                break;
                            }
                            var comprehensiveReport = await provider.GetComprehensiveDriverCheckAsync(driverPath);
                            Console.WriteLine("\nComprehensive Security Report:");
                            Console.WriteLine($"Driver: {comprehensiveReport.DriverName}");
                            Console.WriteLine($"Path: {comprehensiveReport.Path}");
                            Console.WriteLine($"Hash: {comprehensiveReport.Hash}");
                            Console.WriteLine($"\nLolDrivers Check:");
                            Console.WriteLine($"- Vulnerable: {comprehensiveReport.LolDriversCheck.IsVulnerable}");
                            if (comprehensiveReport.LolDriversCheck.VulnerabilityDetails != null)
                            {
                                Console.WriteLine($"- Vulnerability Details: {comprehensiveReport.LolDriversCheck.VulnerabilityDetails.Description}");
                            }
                            Console.WriteLine($"\nMicrosoft Security Check:");
                            Console.WriteLine($"- WDAC Status: {comprehensiveReport.MicrosoftSecurityCheck.WDACStatus.IsAllowed}");
                            Console.WriteLine($"- Signature Status: {comprehensiveReport.MicrosoftSecurityCheck.SignatureStatus.IsValid}");
                            Console.WriteLine($"- Defender Status: {comprehensiveReport.MicrosoftSecurityCheck.DefenderStatus.IsClean}");
                            Console.WriteLine($"\nDriver Analysis:");
                            Console.WriteLine($"- Version: {comprehensiveReport.DriverAnalysis.Version}");
                            Console.WriteLine($"- Publisher: {comprehensiveReport.DriverAnalysis.Publisher}");
                            Console.WriteLine($"- Last Modified: {comprehensiveReport.DriverAnalysis.LastModified}");
                            Console.WriteLine($"\nOverall Security Status: {comprehensiveReport.OverallSecurityStatus}");
                            break;
                        case 0:
                            exit = true;
                            continue;
                        default:
                            Console.WriteLine("Invalid choice!");
                            break;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error: {ex.Message}");
                }
                
                Console.WriteLine("\nPress any key to continue...");
                Console.ReadKey();
            }
        }
    }

    private static void ConfigureServices(IServiceCollection services)
    {
        services.AddLogging(builder =>
        {
            builder.AddConsole();
            builder.AddDebug();
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
        services.AddSingleton<ReportGenerator>();
        services.AddSingleton<DriverAnalyzer>();
        services.AddSingleton<MicrosoftSecurityService>();
        services.AddHttpClient();
    }
}
