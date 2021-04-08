using System.ComponentModel.DataAnnotations;

namespace JwtTenta.Models
{
    public class UpdateRequest
    {
        private string _oldpassword;
        private string _newpassword;
        private string _email;
        private string _phonenumber;
        private string _role;

        [Required]
        public string Username { get; set; }

        [EmailAddress]
        public string? Email
        {
            get => _email;
            set => _email = replaceEmptyWithNull(value);
        }

        public string? Role
        {
            get => _role;
            set => _role = replaceEmptyWithNull(value);
        }

        public string? Phonenumber
        {
            get => _phonenumber;
            set => _phonenumber = replaceEmptyWithNull(value);
        }

        [MinLength(6)]
        public string? OldPassword
        {
            get => _oldpassword;
            set => _oldpassword = replaceEmptyWithNull(value);
        }

        [MinLength(6)]
        public string? NewPassword
        {
            get => _newpassword;
            set => _newpassword = replaceEmptyWithNull(value);
        }

        // helpers

        private string replaceEmptyWithNull(string value)
        {
            // replace empty string with null to make field optional
            return string.IsNullOrEmpty(value) ? null : value;
        }
    }
}