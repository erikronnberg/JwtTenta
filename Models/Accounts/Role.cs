using Microsoft.AspNetCore.Identity;

namespace JwtTenta.Models
{
    public class Role : IdentityRole
    {
        public const string VD = "VD";
        public const string CountryManager = "CountryManager";
        public const string Admin = "Admin";
        public const string Employee = "Employee";
    }
}
