using Gurux.DLMS;
using Gurux.DLMS.Enums;
using Gurux.DLMS.Objects;
using MeterSimulator.DLMS;
using MeterSimulator.Models;

namespace ManyMeterSimulator.ProfileSimulation;

/// <summary>Read-only current metadata for one profile buffer.</summary>
public readonly record struct ProfileBufferState(
    string LogicalName,
    string? Description,
    uint CapturePeriodSeconds,
    uint Capacity,
    uint EntriesInUse,
    DateTimeOffset? LatestCaptureAtUtc);

/// <summary>Result of appending one generated profile record.</summary>
public readonly record struct ProfileCaptureResult(
    string LogicalName,
    DateTimeOffset CapturedAtUtc,
    int RetainedCount,
    int EvictedCount);

/// <summary>
/// Owns ONE batch's shared, mutable profile-simulation object graph. Every meter in the batch
/// builds its <c>DLMSServerSession</c> against the exact same working-XML path (see
/// <see cref="ProfileSimulationStateStore"/>), so <c>TemplateModelCache.Shared.Get</c> — the same
/// cache that shares static templates across a fleet — hands back this identical
/// <see cref="GXDLMSObjectCollection"/> instance to all of them. That is intentional: generation is
/// deterministic and configured identically for every meter in a batch, so there is exactly one
/// timeline of simulated data per batch, not one per meter (the earlier per-meter design is what
/// produced ~20,000 near-duplicate files in production — see ProfileStateRetentionService).
///
/// Buffer mutation locks on the profile's own <c>Buffer</c> object, matching Gurux's own internal
/// convention (selective-access reads already take <c>lock (Buffer)</c> — see
/// TemplateModelCache's remarks) rather than introducing a second, unrelated lock that other code
/// paths reading the same buffer would not know to respect.
///
/// Register/Data values are additionally written onto the shared graph's own objects (so
/// <see cref="Save"/> needs no separate sync step) AND into every currently-materialized meter's own
/// value store, because live reads are answered from there (see DLMSServerSession.PreRead), not
/// from this shared graph.
/// </summary>
public sealed class BatchProfileSimulationState
{
    private readonly object _saveLock = new();
    private readonly GXDLMSObjectCollection _objects;

    public BatchProfileSimulationState(string workingModelPath)
    {
        _objects = TemplateModelCache.Shared.Get(workingModelPath, shiftProfileTimestamps: false);
    }

    /// <summary>Current profile-buffer metadata for every ProfileGeneric in this batch's working model.</summary>
    public IReadOnlyList<ProfileBufferState> GetProfileBufferStates() => _objects
        .OfType<GXDLMSProfileGeneric>()
        .Select(profile => new ProfileBufferState(
            profile.LogicalName,
            profile.Description,
            profile.CapturePeriod,
            profile.ProfileEntries,
            profile.EntriesInUse,
            LatestProfileTimestamp(profile)))
        .OrderBy(profile => profile.LogicalName, StringComparer.Ordinal)
        .ToArray();

    /// <summary>
    /// Appends one simulated capture to a profile buffer and evicts the oldest timestamped record
    /// when the profile has reached its configured capacity. Values are copied from the latest
    /// source row unless a caller has explicitly supplied an increment for that capture object's
    /// logical name. This deliberately does not infer electrical meaning from column position or an
    /// OBIS name.
    /// </summary>
    /// <param name="metersToSync">
    /// Every currently-materialized meter in the batch. Their register/data stores are updated so a
    /// live pull from any of them sees the same values just written to the shared buffer.
    /// </param>
    public ProfileCaptureResult AppendCapture(
        string profileLogicalName,
        DateTimeOffset capturedAtUtc,
        IReadOnlyDictionary<string, decimal>? incrementsByCaptureObject,
        IReadOnlyCollection<DLMSMeter> metersToSync)
    {
        if (_objects.FindByLN(ObjectType.ProfileGeneric, profileLogicalName) is not GXDLMSProfileGeneric profile)
        {
            throw new InvalidOperationException($"Profile '{profileLogicalName}' is not present in this batch's working model.");
        }

        if (profile.ProfileEntries == 0)
        {
            throw new InvalidOperationException($"Profile '{profileLogicalName}' has no configured record capacity.");
        }

        lock (profile.Buffer)
        {
            object[]? sourceRow = LatestProfileRow(profile);
            if (sourceRow is null)
            {
                throw new InvalidOperationException($"Profile '{profileLogicalName}' has no seed row from which to generate a capture.");
            }

            object[] row = new object[sourceRow.Length];
            for (int index = 0; index < sourceRow.Length; index++)
            {
                object? value = CloneProfileCell(sourceRow[index]);
                if (index < profile.CaptureObjects.Count)
                {
                    GXDLMSObject captureObject = profile.CaptureObjects[index].Key;
                    if (captureObject is GXDLMSClock)
                    {
                        value = new GXDateTime(capturedAtUtc.UtcDateTime);
                    }
                    else if (incrementsByCaptureObject is not null
                        && incrementsByCaptureObject.TryGetValue(captureObject.LogicalName, out decimal increment))
                    {
                        value = AddIncrement(value, increment, profileLogicalName, captureObject.LogicalName);
                    }
                }

                row[index] = value!;
            }

            if (ProfileRowTimestamp(profile, row) != capturedAtUtc)
            {
                throw new InvalidOperationException(
                    $"Profile '{profileLogicalName}' has no clock capture column, so its generated record cannot be timestamped safely.");
            }

            profile.Buffer.Add(row);
            int evicted = 0;
            while (profile.Buffer.Count > profile.ProfileEntries)
            {
                int oldest = FindOldestProfileRow(profile);
                if (oldest < 0)
                {
                    profile.Buffer.RemoveAt(profile.Buffer.Count - 1);
                    throw new InvalidOperationException(
                        $"Profile '{profileLogicalName}' exceeded capacity but has a record with no usable capture timestamp. No record was retained.");
                }

                profile.Buffer.RemoveAt(oldest);
                evicted++;
            }

            profile.EntriesInUse = (uint)profile.Buffer.Count;
            SyncCapturedScalars(profile.CaptureObjects.Select((capture, index) => (Capture: capture, Index: index)), row, metersToSync);

            return new ProfileCaptureResult(profileLogicalName, capturedAtUtc, profile.Buffer.Count, evicted);
        }
    }

    /// <summary>
    /// Applies configured increments directly to current scalar values for an Instantaneous-rule
    /// profile — there is no buffer, capacity, or clock column; IP is "the value right now".
    /// </summary>
    public void AdvanceInstantaneous(
        string pushSetupLogicalName,
        IReadOnlyDictionary<string, decimal>? incrementsByCaptureObject,
        IReadOnlyCollection<DLMSMeter> metersToSync)
    {
        if (_objects.FindByLN(ObjectType.PushSetup, pushSetupLogicalName) is not GXDLMSPushSetup push || push.PushObjectList.Count == 0)
        {
            throw new InvalidOperationException(
                $"Instantaneous push setup '{pushSetupLogicalName}' is not present (or has no object list) in this batch's working model.");
        }

        if (incrementsByCaptureObject is null || incrementsByCaptureObject.Count == 0)
        {
            return;
        }

        lock (_saveLock)
        {
            foreach (GXDLMSObject captureObject in push.PushObjectList.Select(item => item.Key))
            {
                if (!incrementsByCaptureObject.TryGetValue(captureObject.LogicalName, out decimal increment))
                {
                    continue;
                }

                object? current = captureObject switch
                {
                    GXDLMSRegister register => register.Value,
                    GXDLMSData data => data.Value,
                    _ => null,
                };

                if (current is null)
                {
                    continue;
                }

                object updated = AddIncrement(current, increment, pushSetupLogicalName, captureObject.LogicalName);
                ApplyScalar(captureObject, updated);
                foreach (DLMSMeter meter in metersToSync)
                {
                    meter.SetValue(captureObject.LogicalName, updated);
                }
            }
        }
    }

    /// <summary>
    /// Serializes the complete current working model to disk. One representative meter session's
    /// <c>SaveWorkingModel</c> should be preferred when a live session is available (it also syncs
    /// that session's — every meter's, since they're identical — Data/Register current values); this
    /// overload exists for when no session is materialized yet.
    /// </summary>
    public void Save(string destinationPath)
    {
        lock (_saveLock)
        {
            _objects.Save(destinationPath, new GXXmlWriterSettings
            {
                Values = true,
                IgnoreDefaultValues = false,
                UseMeterTime = true,
            });

            string xml = File.ReadAllText(destinationPath);
            File.WriteAllText(destinationPath, xml.Replace("+00:00Z", "Z", StringComparison.Ordinal));
        }
    }

    private static void SyncCapturedScalars(
        IEnumerable<(GXKeyValuePair<GXDLMSObject, GXDLMSCaptureObject> Capture, int Index)> captures,
        object[] row,
        IReadOnlyCollection<DLMSMeter> metersToSync)
    {
        foreach (var item in captures)
        {
            // DLMSMeter stores the value returned for an object's normal value attribute
            // (attribute 2). Some profile columns instead capture attributes such as an extended
            // register's CaptureTime. Storing those by logical name would overwrite the register
            // value with a timestamp and corrupt the model when it is saved.
            if (item.Index >= row.Length
                || item.Capture.Value.AttributeIndex != 2
                || item.Capture.Key is not (GXDLMSRegister or GXDLMSData))
            {
                continue;
            }

            ApplyScalar(item.Capture.Key, row[item.Index]);
            foreach (DLMSMeter meter in metersToSync)
            {
                meter.SetValue(item.Capture.Key.LogicalName, row[item.Index]);
            }
        }
    }

    /// <summary>
    /// Keeps the shared graph's own Register/Data objects in sync with what was just generated, so
    /// <see cref="Save"/> needs no separate per-meter sync step. Safe here — unlike the static shared
    /// template — because this object graph is the isolated, per-batch simulation working model.
    /// </summary>
    private static void ApplyScalar(GXDLMSObject captureObject, object value)
    {
        switch (captureObject)
        {
            case GXDLMSRegister register:
                register.Value = value;
                break;
            case GXDLMSData data:
                data.Value = value;
                break;
        }
    }

    private static DateTimeOffset? LatestProfileTimestamp(GXDLMSProfileGeneric profile)
    {
        DateTimeOffset? latest = null;
        foreach (object[] row in profile.Buffer)
        {
            DateTimeOffset? timestamp = ProfileRowTimestamp(profile, row);
            if (timestamp is not null && (latest is null || timestamp > latest))
            {
                latest = timestamp;
            }
        }

        return latest;
    }

    private static object[]? LatestProfileRow(GXDLMSProfileGeneric profile)
    {
        object[]? latestRow = null;
        DateTimeOffset latest = DateTimeOffset.MinValue;
        foreach (object[] row in profile.Buffer)
        {
            DateTimeOffset? timestamp = ProfileRowTimestamp(profile, row);
            if (timestamp is not null && timestamp > latest)
            {
                latest = timestamp.Value;
                latestRow = row;
            }
        }

        return latestRow;
    }

    private static int FindOldestProfileRow(GXDLMSProfileGeneric profile)
    {
        int oldestIndex = -1;
        DateTimeOffset oldest = DateTimeOffset.MaxValue;
        for (int index = 0; index < profile.Buffer.Count; index++)
        {
            DateTimeOffset? timestamp = ProfileRowTimestamp(profile, profile.Buffer[index]);
            if (timestamp is not null && timestamp < oldest)
            {
                oldest = timestamp.Value;
                oldestIndex = index;
            }
        }

        return oldestIndex;
    }

    private static DateTimeOffset? ProfileRowTimestamp(GXDLMSProfileGeneric profile, object[] row)
    {
        for (int index = 0; index < profile.CaptureObjects.Count && index < row.Length; index++)
        {
            if (profile.CaptureObjects[index].Key is GXDLMSClock && row[index] is GXDateTime timestamp)
            {
                return timestamp.Value;
            }
        }

        return null;
    }

    private static object? CloneProfileCell(object? value) => value switch
    {
        GXDateTime timestamp => new GXDateTime(timestamp.Value.UtcDateTime),
        byte[] bytes => bytes.ToArray(),
        _ => value,
    };

    private static object AddIncrement(object? value, decimal increment, string profileLogicalName, string captureLogicalName)
    {
        try
        {
            return value switch
            {
                byte number => checked((byte)(number + increment)),
                sbyte number => checked((sbyte)(number + increment)),
                short number => checked((short)(number + increment)),
                ushort number => checked((ushort)(number + increment)),
                int number => checked((int)(number + increment)),
                uint number => checked((uint)(number + increment)),
                long number => checked((long)(number + increment)),
                ulong number => checked((ulong)(number + increment)),
                float number => checked(number + (float)increment),
                double number => checked(number + (double)increment),
                decimal number => number + increment,
                null => throw new InvalidOperationException("The seed value is null."),
                _ => throw new InvalidOperationException($"The seed value type '{value.GetType().Name}' is not numeric."),
            };
        }
        catch (Exception exception) when (exception is OverflowException or InvalidOperationException)
        {
            throw new InvalidOperationException(
                $"Cannot apply increment {increment} to '{captureLogicalName}' in profile '{profileLogicalName}'. {exception.Message}",
                exception);
        }
    }
}
