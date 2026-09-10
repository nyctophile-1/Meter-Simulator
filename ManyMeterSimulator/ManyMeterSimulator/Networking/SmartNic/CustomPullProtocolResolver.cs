using ManyMeterSimulator.Provisioning;

namespace ManyMeterSimulator.Networking.SmartNic;

/// <summary>
/// Immutable framing facts derived from the batch's HES template. It deliberately contains no
/// DLMS command semantics; its sole purpose is to parse and later encode the correct custom wire
/// shape for this meter.
/// </summary>
public readonly record struct CustomPullProtocolProfile(
    int HesTemplateId,
    CustomPullWireProfile WireProfile,
    uint? ResponseMagicNumber);

/// <summary>
/// Converts persisted batch metadata into a safe custom-pull protocol profile. A malformed or
/// incomplete export leaves custom pull unavailable rather than falling back to guessed widths.
/// </summary>
public sealed class CustomPullProtocolResolver
{
    private readonly HesDataModel _dataModel;

    private readonly IReadOnlyDictionary<int, uint> _responseMagics;

    public CustomPullProtocolResolver(HesDataModel dataModel,
        Microsoft.Extensions.Options.IOptions<CustomPullOptions>? options = null)
    {
        _dataModel = dataModel;
        _responseMagics = options?.Value.ResponseMagicNumbers ?? new Dictionary<int, uint>();
    }

    public bool TryResolve(
        MeterBatch batch,
        out CustomPullProtocolProfile profile,
        out string error)
    {
        profile = default;

        if (batch.HesTemplateId is not int templateId)
        {
            error = $"batch {batch.Id} has no HES template id";
            return false;
        }

        if (!_dataModel.TryGetTemplate(templateId, out MeterTemplateRow template))
        {
            error = $"HES template {templateId} is absent from the configured data model";
            return false;
        }

        if (template.UsesNewHeader)
        {
            IReadOnlyList<uint> magics = _dataModel.GetMagicNumbersForTemplate(templateId);
            if (_responseMagics.TryGetValue(templateId, out uint selected))
            {
                if (!magics.Contains(selected))
                {
                    error = $"response magic {selected} is not registered for HES template {templateId}";
                    return false;
                }
                profile = new CustomPullProtocolProfile(templateId, CustomPullWireProfile.NewHeader, selected);
                error = string.Empty;
                return true;
            }
            if (magics.Count != 1)
            {
                error = magics.Count == 0
                    ? $"new-header HES template {templateId} has no response magic mapping"
                    : $"new-header HES template {templateId} has {magics.Count} response magic mappings; select one explicitly";
                return false;
            }

            profile = new CustomPullProtocolProfile(templateId, CustomPullWireProfile.NewHeader, magics[0]);
            error = string.Empty;
            return true;
        }

        if (template.PullHeaderLength != 10 || template.PushHeaderLength != 10)
        {
            error = $"HES template {templateId} has incompatible custom header lengths " +
                $"push={template.PushHeaderLength}, pull={template.PullHeaderLength}";
            return false;
        }

        profile = new CustomPullProtocolProfile(
            templateId,
            template.IsFG23 ? CustomPullWireProfile.LegacyFg23 : CustomPullWireProfile.Legacy,
            null);
        error = string.Empty;
        return true;
    }
}
