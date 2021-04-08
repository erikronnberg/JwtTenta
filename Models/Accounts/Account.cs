using System;
using System.Collections.Generic;

using Microsoft.AspNetCore.Identity;

namespace JwtTenta.Models
{
    public class Account : IdentityUser
    {
        public DateTime Created { get; set; }
        public DateTime? Updated { get; set; }
        public string JwtToken { get; set; }
        public List<RefreshTokens>? RefreshTokens { get; set; }
        public int EmployeeID { get; set; }

        public bool OwnsToken(string token)
        {
            return RefreshTokens?.Find(x => x.Token == token) != null;
        }
    }
}