using Gurux.DLMS.Objects;
using MeterSimulator.Diagnostics;
using System;
using System.Collections.Concurrent;
using System.Threading;

namespace MeterSimulator.DLMS
{
    /// <summary>
    /// Parses each meter template EXACTLY ONCE and hands the same object collection to every meter
    /// built from it.
    ///
    /// Why this exists: <see cref="MeterObjectLoader.Load"/> reads and parses the whole template XML
    /// (4 MB for Values_SZ0000014HP.xml — 97% of which is ProfileGeneric buffers), deduplicates,
    /// rewires capture objects, fixes buffer data types, shifts timestamps and seeds defaults. Every
    /// step is byte-identical for every meter built from that template, so doing it per meter made a
    /// meter cost megabytes and made a large batch impossible. Sharing makes a meter cost one
    /// reference.
    ///
    /// SAFE TO SHARE — verified against the vendored Gurux source, not assumed:
    ///  • <c>GXDLMSServer.Initialize(true)</c> returns before touching Items, so the server never
    ///    mutates the collection it is given.
    ///  • ProfileGeneric selective access (read by range/entry) builds a NEW list under
    ///    <c>lock (Buffer)</c> and copies row references — it never reorders or edits Buffer.
    ///  • Encoding (<c>GetData</c>) writes only into a local byte buffer and a local type array.
    ///  • <c>GetDataType</c> calls <c>GetAttribute(index, null)</c>, which returns a throwaway when
    ///    the attribute is missing rather than adding it — so concurrent reads cannot race.
    ///
    /// THE ONE RULE: nothing may WRITE to a shared object. A client Set request would do exactly
    /// that (Gurux calls IGXDLMSBase.SetValue when the server leaves e.Handled false), so
    /// <see cref="DLMSServerSession.PreWrite"/> intercepts every Register/Data write and stores it
    /// in the per-meter value store instead. Per-meter divergence lives there; this collection is
    /// the shared, read-only schema.
    /// </summary>
    public sealed class TemplateModelCache
    {
        /// <summary>
        /// Process-wide instance. A template file is immutable on disk and the parse is
        /// deterministic, so this is a pure memoisation keyed by absolute path — and the number of
        /// templates is small and bounded, so nothing needs evicting.
        /// </summary>
        public static readonly TemplateModelCache Shared = new();

        private readonly ConcurrentDictionary<string, Lazy<GXDLMSObjectCollection>> _models =
            new(StringComparer.OrdinalIgnoreCase);

        /// <summary>Number of distinct templates parsed so far. Diagnostics only.</summary>
        public int Count => _models.Count;

        /// <summary>
        /// The shared object model for a template, parsed on first request. Concurrent first-touch
        /// builds it exactly once (<see cref="LazyThreadSafetyMode.ExecutionAndPublication"/>), which
        /// also gives the memory barrier that guarantees no caller observes a half-built model.
        /// </summary>
        public GXDLMSObjectCollection Get(string templatePath)
        {
            if (string.IsNullOrWhiteSpace(templatePath))
            {
                throw new ArgumentException("A meter template (XML) path is required.", nameof(templatePath));
            }

            // Normalised so "Templates/x.xml" and an absolute path to the same file share one entry.
            string key = Path.GetFullPath(templatePath);

            Lazy<GXDLMSObjectCollection> lazy = _models.GetOrAdd(
                key,
                p => new Lazy<GXDLMSObjectCollection>(() => Build(p), LazyThreadSafetyMode.ExecutionAndPublication));

            try
            {
                return lazy.Value;
            }
            catch
            {
                // Never cache a failed parse — a later attempt (e.g. after the file is fixed) retries.
                _models.TryRemove(key, out _);
                throw;
            }
        }

        private static GXDLMSObjectCollection Build(string templatePath)
        {
            var objects = new GXDLMSObjectCollection();
            new MeterObjectLoader(templatePath).Load(objects);

            CoreLog.Debug($"[TemplateCache] Parsed '{Path.GetFileName(templatePath)}' once — " +
                          $"{objects.Count} objects, now shared by every meter using it");

            return objects;
        }
    }
}
