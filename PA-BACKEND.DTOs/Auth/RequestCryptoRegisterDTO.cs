using System.Text.Json.Serialization;

namespace PA_BACKEND.DTOs.Auth
{
    public class RequestCryptoRegisterDTO
    {
        // nombre
        [JsonPropertyName("firstName")]
        public string FirstName { get; set; } = string.Empty;

        // apellido
        [JsonPropertyName("lastName")]
        public string LastName { get; set; } = string.Empty;

        // email
        [JsonPropertyName("email")]
        public string EmailEncrypted { get; set; } = string.Empty;

        // password
        [JsonPropertyName("password")]
        public string PasswordEncrypted { get; set; } = string.Empty;

        // confirmPassword
        [JsonPropertyName("confirmPassword")]
        public string ConfirmPasswordEncrypted { get; set; } = string.Empty;

        // teléfono (opcional)
        [JsonPropertyName("phone")]
        public string? PhoneEncrypted { get; set; }
    }
}
