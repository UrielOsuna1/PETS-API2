using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace PA_BACKEND.DTOs.Auth
{
    public class RequestCryptoLoginDTO
    {
        // correo
        [Required(ErrorMessage = "El correo es obligatorio.")]
        public required string Email { get; set; }

        // contraseña
        [Required(ErrorMessage = "La contraseña es obligatoria.")]
        public required string Password { get; set; }

        // expiración
        [JsonPropertyName("exp")]
        public string? Exp { get; set; }
    }
}