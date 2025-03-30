namespace WindowsDriverInfo.Services;

public class VulnerableDriverComparer : IEqualityComparer<(string Path, string Name, string Hash, LolDriver VulnInfo)>
{
    public bool Equals((string Path, string Name, string Hash, LolDriver VulnInfo) x, 
                      (string Path, string Name, string Hash, LolDriver VulnInfo) y)
    {
        return x.Path.Equals(y.Path, StringComparison.OrdinalIgnoreCase);
    }

    public int GetHashCode((string Path, string Name, string Hash, LolDriver VulnInfo) obj)
    {
        return obj.Path.GetHashCode();
    }
}
