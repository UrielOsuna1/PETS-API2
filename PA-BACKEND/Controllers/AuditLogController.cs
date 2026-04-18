using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
// dtos
using PA_BACKEND.DTOs.AuditLog;
using PA_BACKEND.DTOs.Common;
// interfaces
using PA_BACKEND.Data.Interface;

namespace PA_BACKEND.Controllers
{
    /// <summary>
    /// controller para consultar logs de auditoría.
    /// permite filtrar por usuario, acción, fechas, ip, etc.
    /// </summary>
    [ApiController]
    [Route("api/[controller]")]
    [Authorize(Roles = "SYSADMIN")]
    public class AuditLogController : ControllerBase
    {
        private readonly IAuditLogRepository _auditLogRepository;

        public AuditLogController(IAuditLogRepository auditLogRepository)
        {
            _auditLogRepository = auditLogRepository;
        }

        /// <summary>
        /// consulta logs de auditoría con filtros de búsqueda.
        /// </summary>
        /// <param name="userId">filtro por id de usuario</param>
        /// <param name="action">filtro por acción (ej: LOGIN_SUCCESS)</param>
        /// <param name="entityType">filtro por tipo de entidad</param>
        /// <param name="entityId">filtro por id de entidad</param>
        /// <param name="ipAddress">filtro por dirección ip</param>
        /// <param name="dateFrom">fecha desde (yyyy-MM-dd)</param>
        /// <param name="dateTo">fecha hasta (yyyy-MM-dd)</param>
        /// <param name="limit">límite de resultados (default 50, max 100)</param>
        /// <param name="offset">offset para paginación (default 0)</param>
        /// <returns>lista de logs de auditoría</returns>
        [HttpGet]
        public async Task<IActionResult> GetAuditLogs(
            [FromQuery] int? userId = null,
            [FromQuery] string? action = null,
            [FromQuery] string? entityType = null,
            [FromQuery] int? entityId = null,
            [FromQuery] string? ipAddress = null,
            [FromQuery] DateTime? dateFrom = null,
            [FromQuery] DateTime? dateTo = null,
            [FromQuery] int limit = 50,
            [FromQuery] int offset = 0)
        {
            try
            {
                // validar límites
                if (limit <= 0) limit = 50;
                if (limit > 100) limit = 100;
                if (offset < 0) offset = 0;

                var requestDto = new RequestAuditLogDTO
                {
                    UserId = userId,
                    Action = action,
                    EntityType = entityType,
                    EntityId = entityId,
                    IpAddress = ipAddress,
                    DateFrom = dateFrom,
                    DateTo = dateTo,
                    Limit = limit,
                    Offset = offset
                };

                var logs = await _auditLogRepository.GetAuditLogsAsync(requestDto);

                return Ok(ResponseAPIHelper.SuccessResult(logs, "Logs de auditoría consultados correctamente"));
            }
            catch (ArgumentException ex)
            {
                return BadRequest(ResponseAPIHelper.Fail(ex.Message, ErrorCodes.ValidationError));
            }
            catch (Exception)
            {
                return StatusCode(500, ResponseAPIHelper.Fail(
                    "Error al consultar logs de auditoría",
                    ErrorCodes.InternalError));
            }
        }
    }
}
