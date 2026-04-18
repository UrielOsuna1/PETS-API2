using System.Text.Json;
using PA_BACKEND.DTOs.Auth;
using PA_BACKEND.DTOs.AuditLog;

namespace PA_BACKEND.Data.Interface
{
    public interface IGatewayRepository
    {
        // autentica un usuario con credenciales encriptadas
        Task<ResponseLoginDTO> AuthLoginAsync(string emailEncrypted, string passwordEncrypted, CancellationToken cancellationToken = default);

        // registra un nuevo usuario con campos encriptados
        Task<ResponseLoginDTO> AuthRegisterAsync(RequestCryptoRegisterDTO cryptoDto, CancellationToken cancellationToken = default);

        // refresca el token de acceso (refreshToken encriptado)
        Task<ResponseLoginDTO> AuthRefreshAsync(string refreshTokenEncrypted, CancellationToken cancellationToken = default);

        // cierra sesión del usuario (accessToken plano desde header)
        Task AuthLogoutAsync(int userId, string accessToken, CancellationToken cancellationToken = default);

        // cierra sesión en todos los dispositivos
        Task AuthLogoutAllAsync(int userId, CancellationToken cancellationToken = default);

        // obtiene información de sesión del usuario
        Task<SessionInformationResponseDTO> AuthSessionInfoAsync(int userId, CancellationToken cancellationToken = default);

        // consulta logs de auditoría con filtros
        Task<IEnumerable<ResponseAuditLogDTO>> GetAuditLogsAsync(RequestAuditLogDTO requestDto, CancellationToken cancellationToken = default);
    }
}
