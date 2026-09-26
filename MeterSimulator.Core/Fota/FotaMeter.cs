using System.Collections;
using System.Security.Cryptography;
using Gurux.DLMS;
using Gurux.DLMS.Enums;
using Gurux.DLMS.Objects.Enums;

namespace MeterSimulator.Fota;

public sealed class FotaMeter : IFotaMeter
{
    private readonly IFotaStateStore _store;
    private readonly string _key;
    private readonly Func<FotaSettings> _settings;
    private readonly FotaLimits _limits;

    public FotaMeter(IFotaStateStore store, string key, Func<FotaSettings> settings, FotaLimits limits)
    {
        _store = store;
        _key = key;
        _settings = settings;
        _limits = limits;
    }

    public string? ActiveVersion => _store.Read(_key, state => state.ActiveVersion);

    public object? Read(int attribute)
    {
        FotaSettings configured = _settings();
        return _store.Read<object?>(_key, state =>
        {
            FotaSettings effective = state.Settings ?? configured;
            return attribute switch
            {
                2 => (uint)effective.BlockSize,
                3 => new string(Enumerable.Range(0, state.TotalBlocks).Select(index => state.Blocks.ContainsKey(index) ? '1' : '0').ToArray()),
                4 => (uint)state.FirstMissing(),
                5 => effective.Enabled,
                6 => (byte)state.Status,
                7 => ActivationInfo(state),
                _ => throw new ArgumentOutOfRangeException(nameof(attribute))
            };
        });
    }

    private static GXArray ActivationInfo(FotaState state)
    {
        var result = new GXArray();
        if (state.Status is ImageTransferStatus.VerificationSuccessful or ImageTransferStatus.ActivationSuccessful)
        {
            result.Add(new GXStructure
            {
                (uint)state.ImageSize,
                Convert.FromHexString(state.ImageId),
                Array.Empty<byte>()
            });
        }

        return result;
    }

    public ErrorCode Invoke(int method, object? parameters)
    {
        try
        {
            FotaSettings configured = _settings();
            configured.Validate();
            return _store.Change(_key, state => Decide(state, configured, method, parameters));
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidCastException or OverflowException or FormatException)
        {
            return ErrorCode.UnmatchedType;
        }
    }

    private FotaDecision Decide(FotaState state, FotaSettings configured, int method, object? parameters)
    {
        FotaSettings effective = method == 1 ? configured : state.Settings ?? configured;
        if (!effective.Enabled)
        {
            return new(ErrorCode.ReadWriteDenied);
        }

        if (method == 1)
        {
            if (parameters is not IList values || values.Count != 2 || values[0] is not byte[] id || id.Length is < 1 or > 256 ||
                !TryUnsigned(values[1], out uint size) || size == 0 || size > _limits.MaxImageBytes ||
                ((long)size + effective.BlockSize - 1) / effective.BlockSize > _limits.MaxBlocks)
            {
                return new(ErrorCode.UnmatchedType);
            }

            return new(ErrorCode.Ok, new FotaEvent
            {
                Kind = "init",
                ImageId = Convert.ToHexString(id),
                Size = (int)size,
                Settings = effective with { }
            });
        }

        if (state.Settings is null)
        {
            return new(ErrorCode.ReadWriteDenied);
        }

        if (method == 2)
        {
            return Transfer(state, parameters);
        }

        if (method is 3 or 4 && parameters is not null && (!TryUnsigned(parameters, out uint parameter) || parameter != 0))
        {
            return new(ErrorCode.UnmatchedType);
        }

        if (method == 3)
        {
            if (state.Status is ImageTransferStatus.ActivationSuccessful or ImageTransferStatus.ActivationFailed)
            {
                return new(ErrorCode.ReadWriteDenied);
            }

            bool success = state.Blocks.Count == state.TotalBlocks && !effective.FailVerification;
            return new(success ? ErrorCode.Ok : ErrorCode.OtherReason, new FotaEvent
            {
                Kind = "status",
                Status = success ? ImageTransferStatus.VerificationSuccessful : ImageTransferStatus.VerificationFailed,
                Failure = success ? "" : state.Blocks.Count != state.TotalBlocks ? "Missing image blocks" : "Injected verification failure"
            });
        }

        if (method == 4)
        {
            if (state.Status == ImageTransferStatus.ActivationSuccessful)
            {
                return new(ErrorCode.Ok);
            }

            if (state.Status is not (ImageTransferStatus.VerificationSuccessful or ImageTransferStatus.ActivationFailed))
            {
                return new(ErrorCode.ReadWriteDenied);
            }

            return new(effective.FailActivation ? ErrorCode.OtherReason : ErrorCode.Ok, new FotaEvent
            {
                Kind = "status",
                Status = effective.FailActivation ? ImageTransferStatus.ActivationFailed : ImageTransferStatus.ActivationSuccessful,
                Failure = effective.FailActivation ? "Injected activation failure" : ""
            });
        }

        return new(ErrorCode.ReadWriteDenied);
    }

    private static FotaDecision Transfer(FotaState state, object? parameters)
    {
        if (parameters is not IList values || values.Count != 2 || !TryUnsigned(values[0], out uint index) ||
            index >= state.TotalBlocks || values[1] is not byte[] bytes)
        {
            return new(ErrorCode.UnmatchedType);
        }

        int expected = (int)Math.Min(state.Settings!.BlockSize, state.ImageSize - (long)index * state.Settings.BlockSize);
        if (bytes.Length != expected)
        {
            return new(ErrorCode.UnmatchedType);
        }

        string hash = Convert.ToHexString(SHA256.HashData(bytes));
        if (state.Blocks.TryGetValue((int)index, out string? previous))
        {
            return previous == hash
                ? new(ErrorCode.Ok)
                : new(ErrorCode.OtherReason, new FotaEvent { Kind = "failure", Failure = $"Conflicting duplicate block {index}" });
        }

        if (state.Status is not (ImageTransferStatus.TransferInitiated or ImageTransferStatus.VerificationFailed))
        {
            return new(ErrorCode.ReadWriteDenied);
        }

        if (index == state.Settings.RejectBlock && state.Rejections < state.Settings.RejectAttempts)
        {
            return new(ErrorCode.TemporaryFailure, new FotaEvent
            {
                Kind = "failure",
                Failure = $"Injected rejection of block {index}",
                Rejected = true
            });
        }

        return new(ErrorCode.Ok, new FotaEvent { Kind = "block", Block = (int)index, Hash = hash });
    }

    private static bool TryUnsigned(object? value, out uint result)
    {
        result = 0;
        if (value is not (byte or ushort or uint or sbyte or short or int or long or ulong))
        {
            return false;
        }

        try
        {
            result = Convert.ToUInt32(value);
            return true;
        }
        catch (OverflowException)
        {
            return false;
        }
    }
}
