namespace PA_BACKEND.DTOs.AuditLog
{
    public class InsertAuditLogDTO
    {
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
    }
}
