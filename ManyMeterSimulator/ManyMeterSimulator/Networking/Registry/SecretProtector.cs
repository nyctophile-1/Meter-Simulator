using Microsoft.AspNetCore.DataProtection;

namespace ManyMeterSimulator.Networking.Registry;

/// <summary>
/// Encrypts the one field in the registry that must not be readable on disk: a broker password.
///
/// <para>
/// This exists because the feature broke a standing rule — <c>appsettings.json</c> says in as many
/// words that broker credentials never go in a file — and the registry has to persist them anyway
/// for unattended reconnects. Encrypting the single sensitive field keeps
/// <c>data/network.json</c> readable and diffable for everything an operator needs to debug (host,
/// port, username, TLS) while a copied-off file is not a credential leak.
/// </para>
/// </summary>
public interface ISecretProtector
{
    string Protect(string plaintext);

    /// <summary>
    /// Reverses <see cref="Protect"/>. Never throws: an undecryptable value (a lost key ring, a
    /// hand-edited file) yields empty rather than taking the whole registry down with it. The
    /// broker then fails to authenticate, which is a diagnosable symptom on one row — where losing
    /// the load would silently take every unrelated endpoint with it.
    /// </summary>
    string Unprotect(string ciphertext);
}

/// <inheritdoc />
public sealed class DataProtectionSecretProtector : ISecretProtector
{
    /// <summary>
    /// Purpose string: Data Protection binds ciphertext to it, so a payload from this purpose can
    /// never be unprotected by a different consumer that shares the key ring.
    /// </summary>
    private const string Purpose = "ManyMeterSimulator.NetworkRegistry.BrokerPassword.v1";

    private readonly IDataProtector _protector;
    private readonly ILogger<DataProtectionSecretProtector> _logger;

    public DataProtectionSecretProtector(
        IDataProtectionProvider provider, ILogger<DataProtectionSecretProtector> logger)
    {
        _protector = provider.CreateProtector(Purpose);
        _logger = logger;
    }

    public string Protect(string plaintext) =>
        string.IsNullOrEmpty(plaintext) ? string.Empty : _protector.Protect(plaintext);

    public string Unprotect(string ciphertext)
    {
        if (string.IsNullOrEmpty(ciphertext))
        {
            return string.Empty;
        }

        try
        {
            return _protector.Unprotect(ciphertext);
        }
        catch (Exception ex)
        {
            // Overwhelmingly this means the key ring moved or was lost (see Program.cs — keys are
            // pinned to data/keys/ precisely to stop that). Say so, because the alternative
            // symptom is an authentication failure with no explanation.
            _logger.LogError(
                ex,
                "A stored broker password could not be decrypted — the data-protection key ring at " +
                "data/keys/ is missing or was written by a different app/user. Re-enter the password " +
                "on the Network page to store it under the current keys.");
            return string.Empty;
        }
    }
}
