namespace ManyMeterSimulator.Testing;

public interface ITestPlanStore
{
    IReadOnlyList<TestPlan> Load();
    void Save(IReadOnlyList<TestPlan> plans);
}
