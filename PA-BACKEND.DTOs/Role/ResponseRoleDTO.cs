using System.Text.Json.Serialization;

namespace PA_BACKEND.DTOs.Role
{
    public class ResponseRoleDTO
    {
        // id del rol
        [JsonPropertyName("role_id")]
        public required int IdRole { get; set; }

        // nombre del rol
        [JsonPropertyName("role_name")]
        public required string Name { get; set; }
    }
}