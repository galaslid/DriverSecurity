using System.Text.Json;
using System.Text.Json.Serialization;
using WindowsDriverInfo.Models;
using Microsoft.Win32;
using System.IO;
using System.Security.Cryptography;

namespace WindowsDriverInfo.Services;

public class LolDriversService
{
    private readonly HttpClient _httpClient;
    private const string ApiUrl = "https://www.loldrivers.io/api/drivers.json";
    
    private static List<LolDriver>? _cachedDrivers;
    private static DateTime _lastCacheUpdate;
    private const int CacheExpirationMinutes = 60;
    
    public LolDriversService()
    {
        _httpClient = new HttpClient();
        _httpClient.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
        _httpClient.DefaultRequestHeaders.Add("Accept", "application/json");
    }

    public async Task<List<LolDriver>> GetVulnerableDriversAsync()
    {
        if (_cachedDrivers != null && DateTime.Now.Subtract(_lastCacheUpdate).TotalMinutes < CacheExpirationMinutes)
        {
            return _cachedDrivers;
        }

        try
        {
            var response = await _httpClient.GetAsync(ApiUrl);
            response.EnsureSuccessStatusCode();
            
            var jsonContent = await response.Content.ReadAsStringAsync();
            Console.WriteLine($"Received JSON from API: {jsonContent.Substring(0, Math.Min(500, jsonContent.Length))}...");
            
            var options = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
            };
            
            var drivers = JsonSerializer.Deserialize<List<LolDriver>>(jsonContent, options);
            
            if (drivers != null && drivers.Any())
            {
                Console.WriteLine($"Deserialized {drivers.Count} drivers");
                Console.WriteLine($"First driver description: {drivers[0].Description}");
                _cachedDrivers = drivers;
                _lastCacheUpdate = DateTime.Now;
                return drivers;
            }
            
            return new List<LolDriver>();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error getting vulnerable drivers: {ex.Message}");
            return new List<LolDriver>();
        }
    }

    public List<string> GetSystemDrivers()
    {
        var drivers = new HashSet<string>();
        
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            if (key != null)
            {
                foreach (var subKeyName in key.GetSubKeyNames())
                {
                    try
                    {
                        using var subKey = key.OpenSubKey(subKeyName);
                        var imagePath = subKey?.GetValue("ImagePath")?.ToString();
                        var type = subKey?.GetValue("Type")?.ToString();
                        
                        if (!string.IsNullOrEmpty(imagePath) && type == "1")
                        {
                            var normalizedPath = NormalizePath(imagePath);
                            if (File.Exists(normalizedPath))
                            {
                                drivers.Add(normalizedPath);
                            }
                        }
                    }
                    catch (Exception) { continue; }
                }
            }
        }
        catch (Exception) { }
        
        var systemDriversPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "drivers");
        if (Directory.Exists(systemDriversPath))
        {
            drivers.UnionWith(Directory.GetFiles(systemDriversPath, "*.sys"));
        }

        return drivers.ToList();
    }

    private string NormalizePath(string path)
    {
        path = path.Trim('"');
        
        var replacements = new Dictionary<string, string>
        {
            { "%SystemRoot%", Environment.GetFolderPath(Environment.SpecialFolder.Windows) },
            { "\\??\\", "" },
            { "\\SystemRoot\\", $"{Environment.GetFolderPath(Environment.SpecialFolder.Windows)}\\" }
        };

        foreach (var (key, value) in replacements)
        {
            if (path.Contains(key, StringComparison.OrdinalIgnoreCase))
            {
                path = path.Replace(key, value, StringComparison.OrdinalIgnoreCase);
            }
        }
        
        if (!path.EndsWith(".sys", StringComparison.OrdinalIgnoreCase) && 
            !path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
        {
            path += ".sys";
        }
        
        return path;
    }

    public (bool IsVulnerable, string Description) GetVulnerabilityInfo(string driverPath)
    {
        try
        {
            var driverName = Path.GetFileName(driverPath);
            var hash = CalculateDriverHash(driverPath);
            var vulnerableDrivers = GetVulnerableDriversAsync().GetAwaiter().GetResult();

            foreach (var vulnDriver in vulnerableDrivers)
            {
                if ((vulnDriver.Tags.Any() && driverName.ToLower() == vulnDriver.Tags[0].ToLower()) || 
                    vulnDriver.GetKnownVulnerableSamples().Contains(hash, StringComparer.OrdinalIgnoreCase))
                {
                    return (true, vulnDriver.Description);
                }
            }

            return (false, string.Empty);
        }
        catch
        {
            return (false, "Error checking vulnerability");
        }
    }

    private string CalculateDriverHash(string driverPath)
    {
        using var sha256 = SHA256.Create();
        using var stream = File.OpenRead(driverPath);
        return BitConverter.ToString(sha256.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
    }
}