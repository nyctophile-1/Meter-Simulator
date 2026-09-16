using System.Collections;
using Gurux.DLMS;
using Gurux.DLMS.Objects;

namespace MeterCapture;

public static class ProfileWireValues
{
    public static object[][] Snapshot(object value) => ((IEnumerable)value).Cast<object>()
        .Select(row => ((IEnumerable)row).Cast<object>().Select(Clone).ToArray()).ToArray();

    private static object Clone(object value) => value switch
    {
        byte[] bytes => bytes.ToArray(),
        object[] values => values.Select(Clone).ToArray(),
        _ => value
    };

    public static void Restore(GXDLMSProfileGeneric profile, object[][] rawRows)
    {
        if (profile.Buffer.Count != rawRows.Length || rawRows.Any(r => r.Length != profile.CaptureObjects.Count))
            throw new InvalidDataException("Decoded profile dimensions differ from the wire capture.");
        for (int row = 0; row < rawRows.Length; row++)
            for (int column = 0; column < rawRows[row].Length; column++)
            {
                // Keep Gurux's decoded date representation; numeric values retain their wire type and scale.
                if (rawRows[row][column] is byte[] && profile.Buffer[row][column] is GXDateTime) continue;
                profile.Buffer[row][column] = Clone(rawRows[row][column]);
            }
    }
}
