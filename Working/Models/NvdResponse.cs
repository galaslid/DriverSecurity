namespace WindowsDriverInfo.Models;

public class NvdResponse
{
    public List<NvdVulnerability> Vulnerabilities { get; set; }
}

public class NvdVulnerability
{
    public string Id { get; set; }
    public string Description { get; set; }
    public string Published { get; set; }
}
