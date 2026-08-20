namespace ManyMeterSimulator.Testing;

public sealed class TestPlanRegistry
{
    public const string PullPlanId = "test-pull";
    public const string PushPlanId = "test-push";
    private const string LegacyBasePlanId = "base";
    private const string LegacyQuickPushPlanId = "base-quickpush";

    private readonly List<TestPlan> _plans = new();
    private readonly ITestPlanStore _store;
    private readonly object _lock = new();

    public event Action? Changed;

    public TestPlanRegistry(ITestPlanStore store)
    {
        _store = store;

        var saved = store.Load().ToList();
        lock (_lock)
        {
            // Migrate old plans that have no tasks but still have top-level PushIntervalSec
            _plans.AddRange(saved);

            bool dirty = false;
            // Replace retired defaults once while preserving custom plans and later user choices
            // on the official plans.
            bool hasLegacyDefaults = _plans.Any(p => p.Id is LegacyBasePlanId or LegacyQuickPushPlanId);
            if (hasLegacyDefaults)
            {
                _plans.RemoveAll(p => p.Id is LegacyBasePlanId or LegacyQuickPushPlanId or PullPlanId or PushPlanId);
                _plans.Insert(0, MakePullPlan());
                _plans.Insert(1, MakePushPlan());
                dirty = true;
            }
            else
            {
                if (!_plans.Any(p => p.Id == PullPlanId)) { _plans.Insert(0, MakePullPlan()); dirty = true; }
                if (!_plans.Any(p => p.Id == PushPlanId)) { _plans.Insert(Math.Min(1, _plans.Count), MakePushPlan()); dirty = true; }
            }
            TestPlan? pushPlan = _plans.FirstOrDefault(p => p.Id == PushPlanId);
            TestPlan? pullPlan = _plans.FirstOrDefault(p => p.Id == PullPlanId);
            if (pullPlan is not null && pullPlan.Name != "Pull") { pullPlan.Name = "Pull"; dirty = true; }
            if (pushPlan is not null && pushPlan.Name != "Push") { pushPlan.Name = "Push"; dirty = true; }
            foreach (BurstPushTask task in pushPlan?.Tasks.OfType<BurstPushTask>() ?? Enumerable.Empty<BurstPushTask>())
            {
                if (task.DurationMinutes != 0 || task.OffsetMinutes != 0 || task.BurstCount != 1 || task.MetersPerBatch != 100_000)
                {
                    task.DurationMinutes = 0;
                    task.OffsetMinutes = 0;
                    task.BurstCount = 1;
                    task.MetersPerBatch = 100_000;
                    dirty = true;
                }
            }
            if (dirty) PersistLocked();
        }
    }

    public IReadOnlyList<TestPlan> Plans
    {
        get { lock (_lock) return _plans.ToList(); }
    }

    public TestPlan? Plan(string id)
    {
        lock (_lock)
            return _plans.FirstOrDefault(p => string.Equals(p.Id, id, StringComparison.OrdinalIgnoreCase));
    }

    public void AddPlan(TestPlan plan)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(plan.Name);

        lock (_lock)
        {
            if (_plans.Any(p => string.Equals(p.Name, plan.Name, StringComparison.OrdinalIgnoreCase)))
                throw new ArgumentException($"A plan named '{plan.Name}' already exists.");

            _plans.Add(plan);
            PersistLocked();
        }

        Changed?.Invoke();
    }

    public void UpdatePlan(TestPlan updated)
    {
        lock (_lock)
        {
            int idx = _plans.FindIndex(p => string.Equals(p.Id, updated.Id, StringComparison.OrdinalIgnoreCase));
            if (idx < 0) throw new ArgumentException($"Plan '{updated.Id}' not found.");

            _plans[idx] = updated;
            PersistLocked();
        }

        Changed?.Invoke();
    }

    public bool DeletePlan(string id, out string error)
    {
        lock (_lock)
        {
            TestPlan? plan = _plans.FirstOrDefault(p => string.Equals(p.Id, id, StringComparison.OrdinalIgnoreCase));
            if (plan is null) { error = "Plan not found."; return false; }
            if (plan.IsBasePlan) { error = "The base plan cannot be deleted."; return false; }

            _plans.Remove(plan);
            PersistLocked();
        }

        error = string.Empty;
        Changed?.Invoke();
        return true;
    }

    public void ImportSnapshot(IReadOnlyList<TestPlan> incoming)
    {
        lock (_lock)
        {
            _plans.Clear();
            _plans.Add(MakePullPlan());
            _plans.Add(MakePushPlan());

            foreach (TestPlan p in incoming.Where(p => !p.IsOfficial
                && p.Id is not LegacyBasePlanId and not LegacyQuickPushPlanId
                && p.Id is not PullPlanId and not PushPlanId))
                _plans.Add(p);

            PersistLocked();
        }

        Changed?.Invoke();
    }

    private void PersistLocked() => _store.Save(_plans);

    private static TestPlan MakePullPlan() => new()
    {
        Id = PullPlanId,
        Name = "Pull",
        IsBasePlan = true,
        OfficialKind = OfficialTestKind.Pull,
        Tasks = new List<TestTask>
        {
            new PullListenerTask
            {
                Label = "Pull listener",
                DurationMinutes = 15,
                OffsetMinutes = 0,
            },
        },
    };

    /// <summary>
    /// Stand-in for the old on-demand Push tab: a single burst that fires immediately and
    /// finishes in a minute, so hitting Run behaves like a push button — but still produces
    /// a scored, comparable report like every other plan.
    /// </summary>
    private static TestPlan MakePushPlan() => new()
    {
        Id = PushPlanId,
        Name = "Push",
        IsBasePlan = true,
        OfficialKind = OfficialTestKind.Push,
        Tasks = new List<TestTask>
        {
            new BurstPushTask
            {
                Label = "100k one-shot push",
                BurstCount = 1,
                DurationMinutes = 0,
                OffsetMinutes = 0,
                MetersPerBatch = 100_000,
            },
        },
    };
}
