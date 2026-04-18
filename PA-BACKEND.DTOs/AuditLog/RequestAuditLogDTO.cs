namespace PA_BACKEND.DTOs.AuditLog
{
    public class RequestAuditLogDTO
    {
        // id del usuario
        public int? UserId { get; set; }

        // acción
        public string? Action { get; set; }

        // tipo de entidad
        public string? EntityType { get; set; }

        // id de la entidad
        public int? EntityId { get; set; }

        // dirección ip a buscar
        public string? IpAddress { get; set; }

        // fecha desde (para rango de fechas)
        public DateTime? DateFrom { get; set; }

        // fecha hasta (para rango de fechas)
        public DateTime? DateTo { get; set; }

        // límite de resultados (default 50)
        public int Limit { get; set; } = 50;

        // offset para paginación (default 0)
        public int Offset { get; set; } = 0;
    }
}
