namespace PA_BACKEND.DTOs.Auth
{
    public class SessionInformationDTO
    {
        // nombre del usuario
        public required string FirstName { get; set; }
        
        // apellido del usuario
        public required string LastName { get; set; }
        
        // email del usuario
        public required string Email { get; set; }
        
        // telefono del usuario
        public required string Phone { get; set; }
        
        // fecha de creacion de la sesion
        public required DateTime CreatedAt { get; set; }
    }
}
