namespace ManyMeterSimulator.Testing;

public sealed class TestPlanRegistry
{
    public const string BasePlanId = "base";
    public const string QuickPushPlanId = "base-quickpush";

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
            if (!_plans.Any(p => p.IsBasePlan))
            {
                _plans.Insert(0, MakeBasePlan());
                dirty = true;
            }
            if (!_plans.Any(p => string.Equals(p.Id, QuickPushPlanId, StringComparison.OrdinalIgnoreCase)))
            {
                _plans.Insert(Math.Min(1, _plans.Count), MakeQuickPushPlan());
                dirty = true;
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
            _plans.Add(MakeBasePlan());
            _plans.Add(MakeQuickPushPlan());

            foreach (TestPlan p in incoming.Where(p => !p.IsBasePlan
                && !string.Equals(p.Id, QuickPushPlanId, StringComparison.OrdinalIgnoreCase)))
                _plans.Add(p);

            PersistLocked();
        }

        Changed?.Invoke();
    }

    private void PersistLocked() => _store.Save(_plans);

    private static TestPlan MakeBasePlan() => new()
    {
        Id = BasePlanId,
        Name = "Base Plan",
        IsBasePlan = true,
        Tasks = new List<TestTask>
        {
            new PushLoopTask
            {
                Label = "Standard push loop",
                PushIntervalSec = 300,
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
    private static TestPlan MakeQuickPushPlan() => new()
    {
        Id = QuickPushPlanId,
        Name = "Quick Push",
        IsBasePlan = true,
        Tasks = new List<TestTask>
        {
            new BurstPushTask
            {
                Label = "One-shot push",
                BurstCount = 1,
                DurationMinutes = 1,
                OffsetMinutes = 0,
            },
        },
    };
}
