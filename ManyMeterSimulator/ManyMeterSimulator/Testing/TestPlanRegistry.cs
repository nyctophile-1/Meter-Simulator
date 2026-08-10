namespace ManyMeterSimulator.Testing;

/// <summary>
/// In-memory store of test plans, seeded with a locked base plan on first run.
/// Plans are persisted to JSON after every mutation.
/// </summary>
public sealed class TestPlanRegistry
{
    public const string BasePlanId = "base";

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
            _plans.AddRange(saved);

            if (!_plans.Any(p => p.IsBasePlan))
            {
                _plans.Insert(0, MakeBasePlan());
                PersistLocked();
            }
        }
    }

    public IReadOnlyList<TestPlan> Plans
    {
        get { lock (_lock) return _plans.ToList(); }
    }

    public TestPlan? Plan(string id)
    {
        lock (_lock)
        {
            return _plans.FirstOrDefault(p => string.Equals(p.Id, id, StringComparison.OrdinalIgnoreCase));
        }
    }

    public void AddPlan(TestPlan plan)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(plan.Name);

        lock (_lock)
        {
            if (_plans.Any(p => string.Equals(p.Name, plan.Name, StringComparison.OrdinalIgnoreCase)))
            {
                throw new ArgumentException($"A plan named '{plan.Name}' already exists.");
            }

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
            if (idx < 0)
            {
                throw new ArgumentException($"Plan '{updated.Id}' not found.");
            }

            TestPlan existing = _plans[idx];

            // Honour locked fields
            if (existing.IsFieldLocked(nameof(TestPlan.PushIntervalSec)))
            {
                updated.PushIntervalSec = existing.PushIntervalSec;
            }

            if (existing.IsFieldLocked(nameof(TestPlan.CollectionDurationMin)))
            {
                updated.CollectionDurationMin = existing.CollectionDurationMin;
            }

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

    /// <summary>Replaces all non-base plans with the imported list. Base plan is always re-seeded.</summary>
    public void ImportSnapshot(IReadOnlyList<TestPlan> incoming)
    {
        lock (_lock)
        {
            _plans.Clear();
            _plans.Add(MakeBasePlan());

            foreach (TestPlan p in incoming.Where(p => !p.IsBasePlan))
            {
                _plans.Add(p);
            }

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
        PushIntervalSec = 300,
        CollectionDurationMin = 15,
        LockedFields = new HashSet<string>
        {
            nameof(TestPlan.PushIntervalSec),
            nameof(TestPlan.CollectionDurationMin),
        },
    };
}
