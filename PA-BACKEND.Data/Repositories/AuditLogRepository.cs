using Npgsql;
using Dapper;
using Microsoft.Extensions.Configuration;
// dtos
using PA_BACKEND.DTOs.AuditLog;
using PA_BACKEND.DTOs.Common;
// interfaces
using PA_BACKEND.Data.Interface;

namespace PA_BACKEND.Data.Repositories
{
    /// <summary>
    /// repositorio para operaciones de auditoría y logs del sistema.
    /// contiene métodos privados para uso interno de la api.
    /// </summary>
    public class AuditLogRepository : IAuditLogRepository
    {
        private readonly PostgreSQLConfiguration _configuration;
        private readonly IConfiguration _appConfiguration;

        public AuditLogRepository(PostgreSQLConfiguration configuration, IConfiguration appConfiguration)
        {
            _configuration = configuration;
            _appConfiguration = appConfiguration;
        }

        protected NpgsqlConnection GetConnection()
            => new NpgsqlConnection(_configuration.GetConnection().ConnectionString);

        /// <summary>
        /// inserta un registro de auditoría en la base de datos.
        /// flujo: valida datos -> conecta a BD -> ejecuta función insert_audit_log -> retorna respuesta
        /// nota: este método es para uso interno de la API.
        /// </summary>
        /// <param name="auditLogDto">datos del registro de auditoría</param>
        /// <returns>DTO con los datos del registro insertado</returns>
        #region insertar log de auditoría
        public async Task<ResponseAuditLogDTO> InsertAuditLogAsync(InsertAuditLogDTO auditLogDto)
        {
            if (auditLogDto == null)
                throw new ArgumentNullException(nameof(auditLogDto));

            if (string.IsNullOrWhiteSpace(auditLogDto.Action))
                throw new ArgumentException("Acción requerida");

            try
            {
                using var connection = GetConnection();
                await connection.OpenAsync();

                // la función retorna un tipo compuesto audit_logs
                // leemos como dynamic y mapeamos manualmente para manejar el tipo inet
                var row = await connection.QuerySingleAsync<dynamic>(
                    "SELECT * FROM insert_audit_log(@p_user_id, @p_action, @p_entity_type, @p_entity_id, @p_ip_address::inet)",
                    new
                    {
                        p_user_id = auditLogDto.UserId,
                        p_action = auditLogDto.Action,
                        p_entity_type = auditLogDto.EntityType,
                        p_entity_id = auditLogDto.EntityId,
                        p_ip_address = auditLogDto.IpAddress
                    }
                );

                // mapear manualmente el resultado
                var result = new ResponseAuditLogDTO
                {
                    Id = (int)row.id,
                    UserId = (int)row.user_id,
                    Action = (string)row.action,
                    EntityType = (string)row.entity_type,
                    EntityId = (int)row.entity_id,
                    IpAddress = row.ip_address?.ToString() ?? string.Empty,
                    CreatedAt = (DateTime)row.created_at
                };

                return result;
            }
            catch
            {
                // en caso de error, no lanzamos excepción para no interrumpir el flujo principal
                // solo retornamos null para indicar fallo silencioso
                return null!;
            }
        }
        #endregion

        /// <summary>
        /// consulta logs de auditoría con filtros de búsqueda.
        /// flujo: valida filtros -> conecta a BD -> ejecuta función fun_get_audit_logs -> retorna lista
        /// </summary>
        /// <param name="requestDto">filtros de búsqueda</param>
        /// <returns>lista de logs de auditoría que coinciden con los filtros</returns>
        #region consultar logs de auditoría
        public async Task<IEnumerable<ResponseAuditLogDTO>> GetAuditLogsAsync(RequestAuditLogDTO requestDto)
        {
            if (requestDto == null)
                throw new ArgumentNullException(nameof(requestDto));

            // Debug logging
            Console.WriteLine($"[DEBUG] GetAuditLogsAsync - Received parameters:");
            Console.WriteLine($"  UserId: {requestDto.UserId}");
            Console.WriteLine($"  Action: {requestDto.Action}");
            Console.WriteLine($"  EntityType: {requestDto.EntityType}");
            Console.WriteLine($"  EntityId: {requestDto.EntityId}");
            Console.WriteLine($"  IpAddress: {requestDto.IpAddress}");
            Console.WriteLine($"  DateFrom: {requestDto.DateFrom}");
            Console.WriteLine($"  DateTo: {requestDto.DateTo}");
            Console.WriteLine($"  Limit: {requestDto.Limit}");
            Console.WriteLine($"  Offset: {requestDto.Offset}");

            try
            {
                using var connection = GetConnection();
                await connection.OpenAsync();

                // ejecutar la función con los parámetros de búsqueda
                var rows = await connection.QueryAsync<dynamic>(
                    "SELECT * FROM fun_get_audit_logs(@p_user_id, @p_action, @p_entity_type, @p_entity_id, @p_ip_address, @p_date_from, @p_date_to, @p_limit, @p_offset)",
                    new
                    {
                        p_user_id = requestDto.UserId,
                        p_action = requestDto.Action,
                        p_entity_type = requestDto.EntityType,
                        p_entity_id = requestDto.EntityId,
                        p_ip_address = requestDto.IpAddress,
                        p_date_from = requestDto.DateFrom,
                        p_date_to = requestDto.DateTo,
                        p_limit = requestDto.Limit,
                        p_offset = requestDto.Offset
                    }
                );

                // Debug logging
                Console.WriteLine($"[DEBUG] GetAuditLogsAsync - Query returned {rows.Count()} rows");
                
                // mapear resultados
                var results = rows.Select(row => new ResponseAuditLogDTO
                {
                    Id = (int)row.id,
                    UserId = (int)row.user_id,
                    Action = (string)row.action,
                    EntityType = (string)row.entity_type,
                    EntityId = (int)row.entity_id,
                    IpAddress = row.ip_address?.ToString() ?? string.Empty,
                    CreatedAt = (DateTime)row.created_at
                }).ToList();

                Console.WriteLine($"[DEBUG] GetAuditLogsAsync - Mapped {results.Count} results");
                
                // Debug: Show first few actions
                if (results.Count > 0)
                {
                    var actions = results.Take(5).Select(r => r.Action).ToList();
                    Console.WriteLine($"[DEBUG] GetAuditLogsAsync - First 5 actions: {string.Join(", ", actions)}");
                }

                return results;
            }
            catch
            {
                // en caso de error, retornar lista vacía
                return new List<ResponseAuditLogDTO>();
            }
        }
        #endregion
    }
}
