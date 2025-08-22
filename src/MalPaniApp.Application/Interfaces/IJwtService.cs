using System.Security.Claims;

namespace MalPaniApp.Application.Interfaces
{
    public interface IJwtService
    {
        string GenerateToken(IUserData user, IList<string> roles);
        ClaimsPrincipal? ValidateToken(string token);
        DateTime GetTokenExpiration();
    }

    // Minimal abstraction for user data needed for JWT
    public interface IUserData
    {
        string Id { get; }
        string? UserName { get; }
        string? Email { get; }
        string? FirstName { get; }
        string? LastName { get; }
    }
}
