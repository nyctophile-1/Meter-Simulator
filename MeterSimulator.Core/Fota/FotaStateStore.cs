using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Gurux.DLMS.Enums;
using Gurux.DLMS.Objects.Enums;

namespace MeterSimulator.Fota;

public sealed class FotaStateStore : IFotaStateStore
{
    private readonly string _root;
    private readonly FotaLimits _limits;
    private readonly object _gate = new();
    private readonly Dictionary<string, FotaState> _cache = new();
    private readonly LinkedList<string> _lru = new();

    public FotaStateStore(string root, FotaLimits limits)
    {
        limits.Validate();
        _root = Path.GetFullPath(root);
        _limits = limits;
    }

    public int CachedMeterCount
    {
        get
        {
            lock (_gate)
            {
                return _cache.Count;
            }
        }
    }

    public T Read<T>(string key, Func<FotaState, T> read)
    {
        lock (_gate)
        {
            try
            {
                return read(Load(key));
            }
            finally
            {
                if (!_cache.ContainsKey(key))
                {
                    _lru.Remove(key);
                }

                Trim();
            }
        }
    }

    public ErrorCode Change(string key, Func<FotaState, FotaDecision> decide)
    {
        lock (_gate)
        {
            try
            {
                FotaState state = Load(key);
                FotaDecision decision = decide(state);
                if (decision.Event is not FotaEvent entry)
                {
                    return decision.Error;
                }

                entry.Sequence = state.Sequence + 1;
                string path = BasePath(key);
                Directory.CreateDirectory(_root);

                // Snapshot first; sequence numbers make replay safe if journal truncation is interrupted.
                if (state.Sequence > 0 && state.Sequence % 256 == 0)
                {
                    WriteAtomic(path + ".snapshot", state);
                    using var truncate = new FileStream(path + ".journal", FileMode.Create, FileAccess.Write);
                    truncate.Flush(true);
                }

                byte[] bytes = Encoding.UTF8.GetBytes(Pack(entry) + "\n");
                using (var stream = new FileStream(path + ".journal", FileMode.Append, FileAccess.Write, FileShare.Read))
                {
                    stream.Write(bytes);
                    stream.Flush(true);
                }

                Apply(state, entry);
                return decision.Error;
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
            {
                // Reload after an uncertain write, including a partially appended final record.
                _cache.Remove(key);
                _lru.Remove(key);
                return ErrorCode.TemporaryFailure;
            }
            finally
            {
                Trim();
            }
        }
    }

    private FotaState Load(string key)
    {
        _lru.Remove(key);
        _lru.AddLast(key);
        if (_cache.TryGetValue(key, out FotaState? cached))
        {
            return cached;
        }

        string path = BasePath(key);
        CheckFileSize(path + ".snapshot", (long)_limits.MaxBlocks * 100 + 32768);
        CheckFileSize(path + ".journal", 2 * 1024 * 1024);
        var state = File.Exists(path + ".snapshot")
            ? Unpack<FotaState>(File.ReadAllText(path + ".snapshot"))
            : new FotaState();

        if (File.Exists(path + ".journal"))
        {
            byte[] bytes = File.ReadAllBytes(path + ".journal");
            int completeLength = Array.LastIndexOf(bytes, (byte)'\n') + 1;
            string text = Encoding.UTF8.GetString(bytes, 0, completeLength);
            foreach (string line in text.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                FotaEvent entry = Unpack<FotaEvent>(line);
                if (entry.Sequence <= state.Sequence)
                {
                    continue;
                }

                if (entry.Sequence != state.Sequence + 1)
                {
                    throw new IOException("FOTA journal sequence is incomplete.");
                }

                Apply(state, entry);
            }

            if (completeLength != bytes.Length)
            {
                using var repair = new FileStream(path + ".journal", FileMode.Open, FileAccess.Write);
                repair.SetLength(completeLength);
                repair.Flush(true);
            }
        }

        if (state.ImageSize > _limits.MaxImageBytes || state.TotalBlocks > _limits.MaxBlocks)
        {
            throw new IOException("Persisted FOTA transfer exceeds configured limits; restore the previous limits or reset it explicitly.");
        }

        _cache[key] = state;
        return state;
    }

    private static void CheckFileSize(string path, long maximum)
    {
        if (File.Exists(path) && new FileInfo(path).Length > maximum)
        {
            throw new IOException("FOTA state file exceeds the bounded record size.");
        }
    }

    private void Trim()
    {
        int blocks = _cache.Values.Sum(state => state.Blocks.Count);
        while (_cache.Count > _limits.CachedMeters || blocks > _limits.CachedBlocks)
        {
            string key = _lru.First!.Value;
            _lru.RemoveFirst();
            if (_cache.Remove(key, out FotaState? state))
            {
                blocks -= state.Blocks.Count;
            }
        }
    }

    private string BasePath(string key) => Path.Combine(_root, Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(key))));

    internal static void Apply(FotaState state, FotaEvent entry)
    {
        switch (entry.Kind)
        {
            case "init":
                state.ImageId = entry.ImageId;
                state.ImageSize = entry.Size;
                state.Settings = entry.Settings!;
                state.TotalBlocks = (int)(((long)entry.Size + entry.Settings!.BlockSize - 1) / entry.Settings.BlockSize);
                state.Blocks.Clear();
                state.Rejections = 0;
                state.Status = ImageTransferStatus.TransferInitiated;
                break;
            case "block":
                state.Blocks[entry.Block] = entry.Hash;
                state.Status = ImageTransferStatus.TransferInitiated;
                break;
            case "status":
                state.Status = entry.Status;
                if (entry.Status == ImageTransferStatus.ActivationSuccessful)
                {
                    state.ActiveVersion = state.Settings!.TargetVersion;
                }

                break;
            case "failure":
                if (entry.Rejected)
                {
                    state.Rejections++;
                }

                break;
            case "reset":
                state.ImageId = "";
                state.ImageSize = 0;
                state.TotalBlocks = 0;
                state.Settings = null;
                state.Blocks.Clear();
                state.Rejections = 0;
                state.Status = ImageTransferStatus.NotInitiated;
                break;
            default:
                throw new IOException("Unknown FOTA journal operation.");
        }

        state.LastFailure = entry.Failure;
        state.Sequence = entry.Sequence;
    }

    public static void WriteAtomic<T>(string path, T value)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        byte[] bytes = Encoding.UTF8.GetBytes(Pack(value));
        string temp = path + ".tmp";
        using (var stream = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            stream.Write(bytes);
            stream.Flush(true);
        }

        File.Move(temp, path, true);
    }

    public static T ReadDocument<T>(string path) => Unpack<T>(File.ReadAllText(path));

    private static string Pack<T>(T value)
    {
        string json = JsonSerializer.Serialize(value);
        string hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(json)));
        return hash + " " + json;
    }

    private static T Unpack<T>(string record)
    {
        if (record.Length < 66 || record[64] != ' ')
        {
            throw new IOException("Incomplete FOTA record.");
        }

        string json = record[65..];
        string hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(json)));
        if (!string.Equals(hash, record[..64], StringComparison.Ordinal))
        {
            throw new IOException("FOTA record checksum mismatch.");
        }

        return JsonSerializer.Deserialize<T>(json) ?? throw new IOException("Empty FOTA record.");
    }
}
