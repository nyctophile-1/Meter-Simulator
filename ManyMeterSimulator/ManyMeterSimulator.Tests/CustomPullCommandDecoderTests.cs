using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Networking.SmartNic;
using MeterSimulator.Models;
using Xunit;

namespace ManyMeterSimulator.Tests;

public class CustomPullCommandDecoderTests
{
    private static readonly MeterRef Meter = new(42, NicType.MqttWirepas);

    [Theory]
    [InlineData(4, CustomPullWireSelector.GetWithDateRange, CustomCommandType.GetBlockLoadProfile)]
    [InlineData(72, CustomPullWireSelector.GetWithEntryRange, CustomCommandType.GetBlockLoadProfile)]
    [InlineData(90, CustomPullWireSelector.GetWithoutData, CustomCommandType.GetDiData)]
    [InlineData(83, CustomPullWireSelector.GetWithoutData, CustomCommandType.GetDiData)]
    [InlineData(24, CustomPullWireSelector.GetWithoutData, CustomCommandType.GetNamePlate)]
    public void MapsExplicitWireCommandsAndAliases(
        byte rawCommand,
        CustomPullWireSelector selector,
        CustomCommandType expected)
    {
        Assert.True(CustomPullCommandDecoder.TryDecode(Meter, Request(rawCommand, selector), out CommandIntent intent, out string error), error);
        Assert.Equal(expected, intent.Command);
        Assert.Equal(rawCommand, intent.RawCommandType);
        Assert.Equal((CustomDataSelector)(byte)selector, intent.Selector);
        Assert.Equal(0x01020304u, intent.FrameId);
    }

    [Theory]
    [InlineData(3, CustomPullWireSelector.GetWithDateRange)]
    [InlineData(24, CustomPullWireSelector.SetWithData)]
    [InlineData(4, CustomPullWireSelector.SetWithDate)]
    [InlineData(127, CustomPullWireSelector.GetWithoutData)]
    public void RejectsUnsupportedCommandsAndSelectorPairs(byte rawCommand, CustomPullWireSelector selector)
    {
        Assert.False(CustomPullCommandDecoder.TryDecode(Meter, Request(rawCommand, selector), out _, out string error));
        Assert.NotEmpty(error);
    }

    private static CustomPullRequest Request(byte command, CustomPullWireSelector selector) => new(
        TotalFragments: 1,
        FragmentId: 1,
        FrameId: 0x01020304,
        FromNodeId: 42,
        ToNodeId: 42,
        RawCommandType: command,
        Selector: selector,
        DataLength: 0,
        ValueFromBits: 7,
        ValueToBits: 9);
}
