namespace ManyMeterSimulator.Auth;

/// <summary>
/// One shared password per role - not per-user accounts. Deliberately simple: this is an
/// internal tool for a small team, not a system that needs individual identity/audit trails.
/// </summary>
public class AuthOptions
{
    public const string SectionName = "Auth";

    public required string AdminPassword { get; set; }

    public required string UtilityPassword { get; set; }

    public required string ViewerPassword { get; set; }
}
