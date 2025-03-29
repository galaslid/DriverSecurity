namespace WindowsDriverInfo.Services;

public class DriverCheckCache
{
    private readonly Dictionary<string, (bool IsVulnerable, DateTime CheckTime)> _cache = new();
    private readonly TimeSpan _cacheTimeout;

    public DriverCheckCache(TimeSpan cacheTimeout)
    {
        _cacheTimeout = cacheTimeout;
    }

    public bool TryGetCachedResult(string driverPath, out bool isVulnerable)
    {
        if (_cache.TryGetValue(driverPath, out var cached))
        {
            if (DateTime.Now - cached.CheckTime < _cacheTimeout)
            {
                isVulnerable = cached.IsVulnerable;
                return true;
            }
        }
        isVulnerable = false;
        return false;
    }

    public void CacheResult(string driverPath, bool isVulnerable)
    {
        _cache[driverPath] = (isVulnerable, DateTime.Now);
    }
}