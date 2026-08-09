using System.Text;
using ManyMeterSimulator.Auth;

namespace ManyMeterSimulator.Provisioning;

/// <summary>
/// Download endpoint for the whole-config bundle (batches + network endpoints).
///
/// <para>
/// Admin only, not merely authenticated like the meter CSV: the bundle contains broker passwords in
/// plaintext (it has to, to be portable — see <see cref="ConfigBundle"/>), so it is a secret, and
/// only the role that can change the config may take a copy of it.
/// </para>
/// </summary>
public static class ConfigEndpoints
{
    public static void MapConfigEndpoints(this WebApplication app)
    {
        app.MapGet("/config/export.json", (ConfigBundleService bundles, HttpContext http) =>
            {
                // Stamp the source host into the file so an operator staring at three exports can
                // tell which deployment each came from.
                string json = bundles.Export(exportedFrom: http.Request.Host.Host);

                string fileName = $"maya-config-{DateTimeOffset.UtcNow:yyyyMMdd-HHmmss}.json";
                return Results.File(
                    Encoding.UTF8.GetBytes(json), "application/json", fileName);
            })
            .RequireAuthorization(policy => policy.RequireRole(AppRoles.Admin));
    }
}
