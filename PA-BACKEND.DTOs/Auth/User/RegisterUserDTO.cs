using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;

namespace PA_BACKEND.DTOs.Auth
{
    public class RegisterUserDTO : IValidatableObject
    {
        private string _email = string.Empty;

        [Required(ErrorMessage = "El nombre es obligatorio.")]
        [MaxLength(100, ErrorMessage = "El nombre no puede exceder los 100 caracteres.")]
        [RegularExpression(@"^[a-zA-ZáéíóúÁÉÍÓÚñÑ\s]+$", ErrorMessage = "El nombre solo puede contener letras.")]
        public required string FirstName { get; set; }

        [Required(ErrorMessage = "El apellido es obligatorio.")]
        [MaxLength(100, ErrorMessage = "El apellido no puede exceder los 100 caracteres.")]
        [RegularExpression(@"^[a-zA-ZáéíóúÁÉÍÓÚñÑ\s]+$", ErrorMessage = "El apellido solo puede contener letras.")]
        public required string LastName { get; set; }

        [Required(ErrorMessage = "El correo es obligatorio.")]
        [EmailAddress(ErrorMessage = "El formato del correo no es válido.")]
        public required string Email
        {
            get => _email;
            set => _email = value?.Trim().ToLowerInvariant() ?? string.Empty;
        }

        [Required(ErrorMessage = "La contraseña es obligatoria.")]
        public required string Password { get; set; }

        [Required(ErrorMessage = "Confirma tu contraseña.")]
        [Compare("Password", ErrorMessage = "Las contraseñas no coinciden.")]
        public required string ConfirmPassword { get; set; }

        [RegularExpression(@"^\d{10}$", ErrorMessage = "El teléfono debe contener exactamente 10 números.")]
        public string? Phone { get; set; }

        public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
        {
            var results = new List<ValidationResult>();

            if (Password.Length < 8 || Password.Length > 25)
                results.Add(new ValidationResult(
                    "La contraseña debe tener entre 8 y 25 caracteres.",
                    new[] { nameof(Password) }));

            if (Password.Contains(" "))
                results.Add(new ValidationResult(
                    "La contraseña no debe contener espacios.",
                    new[] { nameof(Password) }));

            var hasUpper   = new Regex(@"[A-Z]+");
            var hasLower   = new Regex(@"[a-z]+");
            var hasNumber  = new Regex(@"[0-9]+");
            var hasSpecial = new Regex(@"[\W_]+");

            if (!hasUpper.IsMatch(Password))
                results.Add(new ValidationResult(
                    "La contraseña debe tener al menos una mayúscula.",
                    new[] { nameof(Password) }));

            if (!hasLower.IsMatch(Password))
                results.Add(new ValidationResult(
                    "La contraseña debe tener al menos una minúscula.",
                    new[] { nameof(Password) }));

            if (!hasNumber.IsMatch(Password))
                results.Add(new ValidationResult(
                    "La contraseña debe tener al menos un número.",
                    new[] { nameof(Password) }));

            if (!hasSpecial.IsMatch(Password))
                results.Add(new ValidationResult(
                    "La contraseña debe tener al menos un carácter especial.",
                    new[] { nameof(Password) }));

            return results;
        }
    }
}