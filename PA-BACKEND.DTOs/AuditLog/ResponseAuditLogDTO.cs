namespace PA_BACKEND.DTOs.AuditLog
{
    public class ResponseAuditLogDTO
    {
        // id log
        public int Id { get; set; }

        // id usuario
        public int UserId { get; set; }

        // acción
        public string Action { get; set; } = string.Empty;

        // tipo de entidad afectada
        public string EntityType { get; set; } = string.Empty;

        // id de la entidad afectada
        public int EntityId { get; set; }

        // dirección ip
        public string IpAddress { get; set; } = string.Empty;

        // fecha y hora de creación
        public DateTime CreatedAt { get; set; }
    }
}
