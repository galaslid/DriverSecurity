using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Net.Http.Json;
using System.Threading.Tasks;

namespace Working.Services
{
    public class VulnerableDriverVersionService
    {
        private readonly ILogger<VulnerableDriverVersionService> _logger;
        private readonly HttpClient _httpClient;
        private readonly string _lolDriversApiUrl = "https://www.loldrivers.io/api/v1/drivers";
        private readonly string _nvdApiUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0";
        private readonly List<VulnerableDriverVersion> _vulnerableVersions = new();

        public VulnerableDriverVersionService(
            ILogger<VulnerableDriverVersionService> logger,
            HttpClient httpClient)
        {
            _logger = logger;
            _httpClient = httpClient;
        }

        public async Task UpdateVulnerableVersionsDatabaseAsync()
        {
            try
            {
                // Получаем данные из LolDrivers
                var lolDriversResponse = await _httpClient.GetAsync(_lolDriversApiUrl);
                if (lolDriversResponse.IsSuccessStatusCode)
                {
                    var lolDriversData = await lolDriversResponse.Content.ReadFromJsonAsync<List<LolDriver>>();
                    foreach (var driver in lolDriversData)
                    {
                        // Добавляем информацию об уязвимых версиях
                        _vulnerableVersions.Add(new VulnerableDriverVersion
                        {
                            CompanyName = driver.Company,
                            DriverName = driver.Name,
                            VulnerableVersion = driver.Version,
                            Description = driver.Description,
                            CVE = driver.CVE,
                            DiscoveryDate = DateTime.Parse(driver.DiscoveryDate)
                        });
                    }
                }

                // Получаем данные из NVD
                var nvdResponse = await _httpClient.GetAsync($"{_nvdApiUrl}?keywordSearch=driver&resultsPerPage=100");
                if (nvdResponse.IsSuccessStatusCode)
                {
                    var nvdData = await nvdResponse.Content.ReadFromJsonAsync<NvdResponse>();
                    foreach (var cve in nvdData.Vulnerabilities)
                    {
                        // Добавляем информацию об уязвимостях драйверов
                        if (cve.Description.Contains("driver", StringComparison.OrdinalIgnoreCase))
                        {
                            _vulnerableVersions.Add(new VulnerableDriverVersion
                            {
                                CompanyName = "Various",
                                DriverName = "Driver-related vulnerability",
                                VulnerableVersion = "Various",
                                Description = cve.Description,
                                CVE = cve.Id,
                                DiscoveryDate = DateTime.Parse(cve.Published)
                            });
                        }
                    }
                }

                _logger.LogInformation("Successfully updated vulnerable versions database");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating vulnerable versions database");
            }
        }
    }
}
