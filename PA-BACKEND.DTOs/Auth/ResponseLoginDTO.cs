namespace PA_BACKEND.DTOs.Auth
{
    public class ResponseLoginDTO
    {
        // token de acceso
        public required string AccessToken { get; set; }
        
        // refresh token
        public required string RefreshToken { get; set; }
    }
}