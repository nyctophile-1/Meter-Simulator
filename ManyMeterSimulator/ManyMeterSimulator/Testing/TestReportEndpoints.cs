using System.Text;
using ManyMeterSimulator.Auth;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ManyMeterSimulator.Testing;

public static class TestReportEndpoints
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    public static void MapTestReportEndpoints(this WebApplication app)
    {
        // Download a single report by run ID
        app.MapGet("/reports/{runId}.json", (string runId, TestRunStore store) =>
            {
                TestRunReport? report = store.Load(runId);
                if (report is null) return Results.NotFound();

                string json = JsonSerializer.Serialize(report, JsonOpts);
                string fileName = $"bench-{report.PlanName.Replace(" ", "-").ToLowerInvariant()}-{report.RunId}.json";
                return Results.File(Encoding.UTF8.GetBytes(json), "application/json", fileName);
            })
            .RequireAuthorization(policy => policy.RequireRole(AppRoles.Admin));
    }
}
