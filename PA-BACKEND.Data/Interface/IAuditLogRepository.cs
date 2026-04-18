using PA_BACKEND.DTOs.AuditLog;
using PA_BACKEND.DTOs.Common;

namespace PA_BACKEND.Data.Interface
{
    public interface IAuditLogRepository
    {
        // método para insertar un registro de auditoría (uso interno de la API)
        Task<ResponseAuditLogDTO> InsertAuditLogAsync(InsertAuditLogDTO auditLogDto);

        // método para consultar logs de auditoría con filtros de búsqueda
        Task<IEnumerable<ResponseAuditLogDTO>> GetAuditLogsAsync(RequestAuditLogDTO requestDto);
    }
}
