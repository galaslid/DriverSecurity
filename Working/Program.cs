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
            Console.WriteLine("4. Check Driver Exposed Devices");
            Console.WriteLine("5. Check WFP Status");
            Console.WriteLine("6. Check for Vulnerable Drivers");
            Console.WriteLine("7. Check Specific Driver");
            Console.WriteLine("8. Get Detailed Driver Info");
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
                            Console.WriteLine(provider.CheckDriverExposedDevices());
                            break;
                        case 5:
                            Console.WriteLine(provider.CheckWFPStatus());
                            break;
                        case 6:
                            await provider.CheckDriversAgainstLolDriversDb();
                            break;
                        case 7:
                            Console.Write("Enter driver name (with .sys extension): ");
                            var driverName = Console.ReadLine();
                            if (string.IsNullOrWhiteSpace(driverName))
                            {
                                Console.WriteLine("Invalid driver name!");
                                break;
                            }
                            if (!driverName.EndsWith(".sys", StringComparison.OrdinalIgnoreCase))
                            {
                                driverName += ".sys";
                            }
                            Console.WriteLine(provider.CheckSpecificDriver(driverName));
                            break;
                        case 8:
                            Console.Write("Enter driver path: ");
                            var driverPath = Console.ReadLine();
                            if (string.IsNullOrWhiteSpace(driverPath))
                            {
                                Console.WriteLine("Invalid driver path!");
                                break;
                            }
                            var detailedInfo = await provider.GetDetailedDriverInfoAsync(driverPath);
                            Console.WriteLine("\nDetailed Driver Information:");
                            Console.WriteLine($"Name: {detailedInfo.DriverName}");
                            Console.WriteLine($"Version: {detailedInfo.Version}");
                            Console.WriteLine($"Publisher: {detailedInfo.Publisher}");
                            Console.WriteLine($"Signed: {detailedInfo.IsSigned}");
                            Console.WriteLine($"Signature Status: {detailedInfo.SignatureStatus}");
                            Console.WriteLine($"Last Modified: {detailedInfo.LastModified}");
                            Console.WriteLine($"File Size: {detailedInfo.FileSize}");
                            Console.WriteLine($"Security Status: {detailedInfo.SecurityStatus}");
                            Console.WriteLine("\nDependencies:");
                            foreach (var dep in detailedInfo.Dependencies)
                            {
                                Console.WriteLine($"- {dep}");
                            }
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
    }
}
