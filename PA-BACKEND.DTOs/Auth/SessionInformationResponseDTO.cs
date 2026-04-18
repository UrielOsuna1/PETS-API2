namespace PA_BACKEND.DTOs.Auth
{
    public class SessionInformationResponseDTO
    {
        public required string FirstName { get; set; }
        
        public required string LastName { get; set; }
        
        public required string Email { get; set; }
        
        public required string Phone { get; set; }
        
        public required string CreatedAt { get; set; }
    }
}
