using MalPaniApp.Application.Interfaces;
using Microsoft.AspNetCore.Identity;

namespace MalPaniApp.Infrastructure.Identity
{
    public class ApplicationUser : IdentityUser, IUserData
    {
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime? UpdatedAt { get; set; }
    }
}
