namespace ManyMeterSimulator.Auth;

/// <summary>
/// Permission model (see implementation.md): Viewer can only see things; Utility can additionally
/// Start/Stop batches; Admin can additionally Create/Delete batches. Admin is a superset of
/// Utility, which is a superset of Viewer - checks below are written accordingly, not as three
/// disjoint roles.
/// </summary>
public static class AppRoles
{
    public const string Admin = "Admin";
    public const string Utility = "Utility";
    public const string Viewer = "Viewer";
}
