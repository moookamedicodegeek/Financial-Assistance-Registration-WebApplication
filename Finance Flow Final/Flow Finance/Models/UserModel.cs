using System.ComponentModel.DataAnnotations;

namespace Flow_Finance.Models
{
    public class UserModel
    {
        public string Uid { get; set; }  // Add the Uid property here
        public string? Id { get; set; }  // This is Firebase-generated Id, nullable to handle cases where it's not set yet.

        [Required(ErrorMessage = "Name is required.")]
        [StringLength(20, ErrorMessage = "Name cannot exceed 20 characters.")]
        public string? Name { get; set; }

        [RegularExpression(@"^\d{6,10}$", ErrorMessage = "ID must be between 6 and 10 digits.")]
        public string? UserId { get; set; } // Custom User ID, renamed to avoid conflict with Firebase-generated 'Id'.

        [Required(ErrorMessage = "Surname is required.")]
        [StringLength(50, ErrorMessage = "Surname cannot exceed 50 characters.")]
        public string? Surname { get; set; }

        [Required(ErrorMessage = "Address is required.")]
        [StringLength(100, ErrorMessage = "Address cannot exceed 100 characters.")]
        public string? Address { get; set; }

        [Required(ErrorMessage = "Date of Birth is required.")]
        [DataType(DataType.Date, ErrorMessage = "Please enter a valid date.")]
        public string? DOB { get; set; }

        [Required(ErrorMessage = "Upload Picture is required.")]
        public string? ImageUrl { get; set; }  // To store the URL of the uploaded picture.

        public string? Email { get; set; }  // Email associated with the user's profile.

        public string CardNumber { get; set; }
    }
}
