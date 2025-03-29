using System.Text.Json;
using System.Text.Json.Serialization;
using WindowsDriverInfo.Models;
using Microsoft.Win32;
using System.IO;

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
            var options = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
            };
            
            var drivers = JsonSerializer.Deserialize<List<LolDriver>>(jsonContent, options);
            
            if (drivers != null && drivers.Any())
            {
                _cachedDrivers = drivers;
                _lastCacheUpdate = DateTime.Now;
                return drivers;
            }
            
            return new List<LolDriver>();
        }
        catch (Exception)
        {
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
}