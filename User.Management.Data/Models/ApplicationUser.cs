using Microsoft.AspNetCore.Identity;

namespace User.Management.Data.Models;

public class ApplicationUser:IdentityUser
{
    public DateTime RefreshToken { get; set; }
    public DateTime RefreshTokenExpiry  { get; set; }
    
}