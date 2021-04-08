using System.ComponentModel.DataAnnotations;

namespace JwtTenta.Models
{
    public class RegisterRequest
    {

        [Required]
        public string Username { get; set; }

        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        [MinLength(6)]
        public string Password { get; set; }

        [Required]
        public int EmployeeID { get; set; }
    }
}