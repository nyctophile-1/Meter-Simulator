namespace ManyMeterSimulator.Networking.Mqtt;

/// <summary>
/// A codec's wiring, in words, so it can be logged at startup and checked against HES without
/// reading any code.
///
/// <para>
/// This exists because the failure mode it guards against is invisible: a codec that subscribes to
/// the wrong filter looks exactly like an HES that is not polling, and a codec that publishes to a
/// topic HES does not subscribe to looks exactly like an HES that ignores our answer. Both are
/// silent. Printing the plan next to <see cref="HesExpects"/> — the filter on HES's side that has
/// to match <see cref="Publish"/> — turns "nothing is happening" into something readable.
/// </para>
/// </summary>
/// <param name="Subscribe">The filter(s) we subscribe to, i.e. where HES's requests arrive.</param>
/// <param name="NodeIdSource">How the meter is identified out of a request — topic or payload.</param>
/// <param name="Publish">The topic pattern our answers are published to.</param>
/// <param name="HesExpects">The subscription on HES's side that <paramref name="Publish"/> must match.</param>
/// <param name="Framing">What wraps the DLMS wrapper frame in each direction.</param>
public sealed record NicTopicPlan(
    string Subscribe,
    string NodeIdSource,
    string Publish,
    string HesExpects,
    string Framing);
