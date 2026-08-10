using System.Text;
using ManyMeterSimulator.Auth;

namespace ManyMeterSimulator.Provisioning;

/// <summary>
/// Download endpoints for each setup page's config file — one per page, matching the three
/// export buttons.
///
/// <para>
/// Admin only, not merely authenticated like the meter CSV: the network file contains broker
/// passwords in plaintext (it has to, to be portable), so only the role that can change the config
/// may take a copy of it. The other two carry no secrets, but are gated the same way for one rule.
/// </para>
/// </summary>
public static class ConfigEndpoints
{
    public static void MapConfigEndpoints(this WebApplication app)
    {
        Download(app, "/config/batches.json", "maya-batches", (b, host) => b.ExportBatches(host));
        Download(app, "/config/network.json", "maya-network", (b, host) => b.ExportNetwork(host));
        Download(app, "/config/badcomm.json", "maya-badcomm", (b, host) => b.ExportBadComm(host));
        Download(app, "/config/testing.json", "maya-testing", (b, host) => b.ExportTesting(host));
        Download(app, "/config/testplans.json", "maya-testplans", (b, host) => b.ExportTestPlans(host));
    }

    private static void Download(
        WebApplication app, string route, string filePrefix, Func<ConfigBundleService, string, string> export)
    {
        app.MapGet(route, (ConfigBundleService bundles, HttpContext http) =>
            {
                // Stamp the source host into the file so an operator staring at several exports can
                // tell which deployment each came from.
                string json = export(bundles, http.Request.Host.Host);
                string fileName = $"{filePrefix}-{DateTimeOffset.UtcNow:yyyyMMdd-HHmmss}.json";
                return Results.File(Encoding.UTF8.GetBytes(json), "application/json", fileName);
            })
            .RequireAuthorization(policy => policy.RequireRole(AppRoles.Admin));
    }
}
