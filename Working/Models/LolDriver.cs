using System.Text.Json.Serialization;

namespace WindowsDriverInfo.Models;

public class LolDriver
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("tags")]
    public List<string> Tags { get; set; } = new();

    [JsonPropertyName("verified")]
    public string Verified { get; set; } = string.Empty;

    [JsonPropertyName("author")]
    public string Author { get; set; } = string.Empty;

    [JsonPropertyName("created")]
    public string Created { get; set; } = string.Empty;

    [JsonPropertyName("mitreId")]
    public string MitreId { get; set; } = string.Empty;

    [JsonPropertyName("category")]
    public string Category { get; set; } = string.Empty;

    [JsonPropertyName("commands")]
    public Commands Commands { get; set; } = new();

    [JsonPropertyName("knownVulnerableSamples")]
    public object KnownVulnerableSamples { get; set; } = new List<string>();

    public List<string> GetKnownVulnerableSamples()
    {
        if (KnownVulnerableSamples is List<string> list)
            return list;
        return new List<string>();
    }
}

public class Commands
{
    [JsonPropertyName("command")]
    public string Command { get; set; } = string.Empty;

    [JsonPropertyName("description")]
    public string Description { get; set; } = string.Empty;

    [JsonPropertyName("operatingSystem")]
    public string OperatingSystem { get; set; } = string.Empty;
}