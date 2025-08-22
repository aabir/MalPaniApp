using MalPaniApp.Application.DTOs.Auth;
using MalPaniApp.Application.Interfaces;
using MalPaniApp.Infrastructure.Identity;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace MalPaniApp.Infrastructure.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IJwtService _jwtService;

        public AuthService(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            IJwtService jwtService)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _jwtService = jwtService;
        }

        public async Task<AuthResponseDto?> RegisterAsync(RegisterDto registerDto)
        {
            var existingUser = await _userManager.FindByEmailAsync(registerDto.Email);
            if (existingUser != null)
                return null; // User already exists

            var user = new ApplicationUser
            {
                UserName = registerDto.Email,
                Email = registerDto.Email,
                FirstName = registerDto.FirstName,
                LastName = registerDto.LastName,
                CreatedAt = DateTime.UtcNow
            };

            var result = await _userManager.CreateAsync(user, registerDto.Password);
            if (!result.Succeeded)
                return null;

            // Add default role (optional)
            await _userManager.AddToRoleAsync(user, "User");

            var roles = await _userManager.GetRolesAsync(user);
            var token = _jwtService.GenerateToken(user, roles);

            return new AuthResponseDto
            {
                Token = token,
                Email = user.Email!,
                FirstName = user.FirstName!,
                LastName = user.LastName!,
                ExpiresAt = _jwtService.GetTokenExpiration()
            };
        }

        public async Task<AuthResponseDto?> LoginAsync(LoginDto loginDto)
        {
            var user = await _userManager.FindByEmailAsync(loginDto.Email);
            if (user == null)
                return null;

            var result = await _signInManager.CheckPasswordSignInAsync(user, loginDto.Password, false);
            if (!result.Succeeded)
                return null;

            var roles = await _userManager.GetRolesAsync(user);
            var token = _jwtService.GenerateToken(user, roles);

            return new AuthResponseDto
            {
                Token = token,
                Email = user.Email!,
                FirstName = user.FirstName!,
                LastName = user.LastName!,
                ExpiresAt = _jwtService.GetTokenExpiration()
            };
        }

        public async Task<bool> LogoutAsync(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return false;

            await _signInManager.SignOutAsync();
            return true;
        }

        public async Task<AuthResponseDto?> RefreshTokenAsync(string token)
        {
            var principal = _jwtService.ValidateToken(token);
            if (principal == null)
                return null;

            var userId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
                return null;

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return null;

            var roles = await _userManager.GetRolesAsync(user);
            var newToken = _jwtService.GenerateToken(user, roles);

            return new AuthResponseDto
            {
                Token = newToken,
                Email = user.Email!,
                FirstName = user.FirstName!,
                LastName = user.LastName!,
                ExpiresAt = _jwtService.GetTokenExpiration()
            };
        }
    }
}
