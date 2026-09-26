using Gurux.DLMS.Enums;
using Gurux.DLMS.Objects.Enums;

namespace MeterSimulator.Fota;

public sealed record FotaSettings
{
    public bool Enabled { get; set; }
    public string TargetVersion { get; set; } = "";
    public int BlockSize { get; set; } = 200;
    public int RejectBlock { get; set; } = -1;
    public int RejectAttempts { get; set; }
    public bool FailVerification { get; set; }
    public bool FailActivation { get; set; }

    public void Validate()
    {
        if (BlockSize is < 32 or > 4096 || RejectBlock < -1 || RejectAttempts is < 0 or > 1000 ||
            TargetVersion.Length > 128 || (Enabled && string.IsNullOrWhiteSpace(TargetVersion)))
        {
            throw new ArgumentException("Use block size 32–4096, attempts 0–1000 and a target version of 1–128 characters when enabled.");
        }
    }
}

public sealed class FotaLimits
{
    public int MaxImageBytes { get; set; } = 16 * 1024 * 1024;
    public int MaxBlocks { get; set; } = 131072;
    public int CachedMeters { get; set; } = 128;
    public int CachedBlocks { get; set; } = 262144;

    public void Validate()
    {
        if (MaxImageBytes is < 1 or > 268435456 || MaxBlocks is < 1 or > 1048576 ||
            CachedMeters is < 1 or > 4096 || CachedBlocks < MaxBlocks || CachedBlocks > 4194304)
        {
            throw new ArgumentException("Invalid FOTA image, block or cache limits.");
        }
    }
}

public sealed class FotaState
{
    public long Sequence { get; set; }
    public string ImageId { get; set; } = "";
    public int ImageSize { get; set; }
    public int TotalBlocks { get; set; }
    public FotaSettings? Settings { get; set; }
    public Dictionary<int, string> Blocks { get; set; } = new();
    public int Rejections { get; set; }
    public ImageTransferStatus Status { get; set; }
    public string? ActiveVersion { get; set; }
    public string LastFailure { get; set; } = "";

    public int FirstMissing()
    {
        int index = 0;
        while (index < TotalBlocks && Blocks.ContainsKey(index))
        {
            index++;
        }

        return index;
    }
}

public sealed record FotaEvent
{
    public long Sequence { get; set; }
    public string Kind { get; set; } = "";
    public string ImageId { get; set; } = "";
    public int Size { get; set; }
    public FotaSettings? Settings { get; set; }
    public int Block { get; set; }
    public string Hash { get; set; } = "";
    public ImageTransferStatus Status { get; set; }
    public string Failure { get; set; } = "";
    public bool Rejected { get; set; }
}

public sealed record FotaDecision(ErrorCode Error, FotaEvent? Event = null);

public interface IFotaStateStore
{
    T Read<T>(string key, Func<FotaState, T> read);
    ErrorCode Change(string key, Func<FotaState, FotaDecision> decide);
}

public interface IFotaMeter
{
    object? Read(int attribute);
    string? ActiveVersion { get; }
    ErrorCode Invoke(int method, object? parameters);
}
