using System;

namespace JwtTenta.Models
{
    public class AccountResponse
    {
        public string Username { get; set; }
        public string Email { get; set; }
        public string Phonenumber { get; set; }
        public DateTime Created { get; set; }
        public DateTime? Updated { get; set; }
        public bool Success { get; set; }
        public string ErrorMessage { get; set; }
    }
}