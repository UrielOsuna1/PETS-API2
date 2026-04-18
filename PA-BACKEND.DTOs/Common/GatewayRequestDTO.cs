using System.Text.Json.Serialization;

namespace PA_BACKEND.DTOs.Common
{
    public class GatewayRequestDTO
    {
        // identificador del endpoint (ej: "auth_login", "auth_register")
        [JsonPropertyName("endpoint")]
        public string Endpoint { get; set; } = string.Empty;

        // timestamp encriptado para validación anti-replay (exp)
        [JsonPropertyName("exp")]
        public string? Exp { get; set; }

        // token de autorización (para endpoints protegidos, opcional si se envía en header)
        [JsonPropertyName("token")]
        public string? Token { get; set; }

        // datos específicos del endpoint (estructura varía según el endpoint)
        [JsonPropertyName("data")]
        public System.Text.Json.JsonElement Data { get; set; }
    }
}
