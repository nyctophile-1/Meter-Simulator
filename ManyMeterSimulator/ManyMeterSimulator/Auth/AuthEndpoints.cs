using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace ManyMeterSimulator.Auth;

public static class AuthEndpoints
{
    public static void MapAuthEndpoints(this WebApplication app)
    {
        app.MapPost("/login", async (HttpContext http, IOptions<AuthOptions> authOptions, [FromForm] string password) =>
        {
            AuthOptions options = authOptions.Value;

            string? matchedRole = password switch
            {
                _ when password == options.AdminPassword => AppRoles.Admin,
                _ when password == options.UtilityPassword => AppRoles.Utility,
                _ when password == options.ViewerPassword => AppRoles.Viewer,
                _ => null,
            };

            if (matchedRole is null)
            {
                return Results.Redirect("/login?error=true");
            }

            // Admin implicitly has everything Utility/Viewer have; Utility implicitly has
            // what Viewer has. Granting all the roles a login is entitled to up front means
            // callers can just check the specific permission they need (e.g. IsInRole(Utility)
            // to gate Start/Stop) without also having to remember to OR in IsInRole(Admin).
            string[] roles = matchedRole switch
            {
                AppRoles.Admin => [AppRoles.Admin, AppRoles.Utility, AppRoles.Viewer],
                AppRoles.Utility => [AppRoles.Utility, AppRoles.Viewer],
                _ => [AppRoles.Viewer],
            };

            var claims = new List<Claim> { new(ClaimTypes.Name, matchedRole) };
            claims.AddRange(roles.Select(r => new Claim(ClaimTypes.Role, r)));

            var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            await http.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));

            return Results.Redirect("/");
        }).DisableAntiforgery();

        app.MapGet("/logout", async (HttpContext http) =>
        {
            await http.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return Results.Redirect("/login");
        });
    }
}
