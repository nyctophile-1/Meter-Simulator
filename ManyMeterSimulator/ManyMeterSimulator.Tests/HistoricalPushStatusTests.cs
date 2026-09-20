using ManyMeterSimulator.Brain;
using ManyMeterSimulator.Components.Pages;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.JSInterop;
using MudBlazor.Services;

namespace ManyMeterSimulator.Tests;

public class HistoricalPushStatusTests
{
    [Fact]
    public async Task RendersCurrentProfileDatesAndMeasuredRatesSeparatelyFromPlannedCounts()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddMudServices();
        services.AddSingleton<IJSRuntime, NoJs>();
        await using var provider = services.BuildServiceProvider();
        await using var renderer = new HtmlRenderer(provider, provider.GetRequiredService<ILoggerFactory>());
        var time = new DateTimeOffset(2026, 9, 15, 18, 30, 0, TimeSpan.Zero);
        var position = new HistoricalPushPosition(7, "RF fleet", "0.5.25.9.0.255", time);
        var progress = new HistoricalPushProgress(time.AddDays(-1), time.AddDays(1), 10000,
            Sent: 150, Skipped: 2, Failed: 1, MessagesSent: 300, Elapsed: TimeSpan.FromSeconds(10))
        {
            CurrentSlot = new(position, 1000, 150, 2, 1, 8),
            LastSuccessfulPush = position,
            CurrentRecordsPerSecond = 25,
            CurrentMessagesPerSecond = 50,
            RateWindowSeconds = 5,
            Profiles = [new(7, "RF fleet", position.Profile, 10000, 150, 2, 1, 300, 0, time, time)]
        };
        var html = await renderer.Dispatcher.InvokeAsync(async () =>
        {
            var component = await renderer.RenderComponentAsync<HistoricalPushStatus>(ParameterView.FromDictionary(
                new Dictionary<string, object?> { [nameof(HistoricalPushStatus.State)] = new HistoricalPushState("Sending", Progress: progress) }));
            return component.ToHtmlString();
        });
        var preview = Environment.GetEnvironmentVariable("MAYA_PROGRESS_PREVIEW");
        if (!string.IsNullOrEmpty(preview))
        {
            await File.WriteAllTextAsync(preview, html);
        }
        Assert.Contains("Sending Block load", html);
        Assert.Contains("16 Sep 2026 00:00:00 IST", html);
        Assert.Contains("2026-09-15 18:30:00 UTC", html);
        Assert.Contains("Actual successful records/sec", html);
        Assert.Contains("Last successful record", html);
        Assert.Contains("25", html);
        Assert.Contains("150", html);
        Assert.DoesNotContain("No record has completed", html);


    }

    private sealed class NoJs : IJSRuntime
    {
        public ValueTask<TValue> InvokeAsync<TValue>(string identifier, object?[]? args) => ValueTask.FromResult(default(TValue)!);

        public ValueTask<TValue> InvokeAsync<TValue>(string identifier, CancellationToken cancellationToken, object?[]? args) =>
            ValueTask.FromResult(default(TValue)!);
    }
}
