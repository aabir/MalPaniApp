using MalPaniApp.Application.DTOs.Auth;

namespace MalPaniApp.Application.Interfaces
{
    public interface IAuthService
    {
        Task<AuthResponseDto?> RegisterAsync(RegisterDto registerDto);
        Task<AuthResponseDto?> LoginAsync(LoginDto loginDto);
        Task<bool> LogoutAsync(string userId);
        Task<AuthResponseDto?> RefreshTokenAsync(string token);
    }
}
