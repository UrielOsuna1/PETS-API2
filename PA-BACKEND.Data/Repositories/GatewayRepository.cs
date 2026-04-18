using PA_BACKEND.DTOs.Auth;
using PA_BACKEND.DTOs.AuditLog;
// interfaces
using Microsoft.Extensions.Logging;
using PA_BACKEND.Data.Interface;

namespace PA_BACKEND.Data.Repositories
{
    /// <summary>
    /// implementación del gateway que orquesta llamadas a los repositorios existentes.
    /// contiene la lógica de desencriptación y enrutamiento.
    /// </summary>
    public class GatewayRepository : IGatewayRepository
    {
        private readonly IAuthRepository _authRepository;
        private readonly IAuditLogRepository _auditLogRepository;
        private readonly ICryptoRepository _cryptoRepository;
        private readonly ILogger<GatewayRepository> _logger;

        public GatewayRepository(
            IAuthRepository authRepository,
            IAuditLogRepository auditLogRepository,
            ICryptoRepository cryptoRepository,
            ILogger<GatewayRepository> logger)
        {
            _authRepository = authRepository;
            _auditLogRepository = auditLogRepository;
            _cryptoRepository = cryptoRepository;
            _logger = logger;
        }

        /// <summary>
        /// procesa solicitud de login a través del gateway.
        /// flujo: recibe credenciales encriptadas -> desencripta -> delega a AuthRepository -> retorna tokens
        /// </summary>
        /// <param name="emailEncrypted">email encriptado</param>
        /// <param name="passwordEncrypted">contraseña encriptada</param>
        /// <param name="cancellationToken">token de cancelación</param>
        /// <returns>tokens de acceso y refresh del usuario autenticado</returns>
        #region login
        public async Task<ResponseLoginDTO> AuthLoginAsync(
            string emailEncrypted, 
            string passwordEncrypted, 
            CancellationToken cancellationToken = default)
        {
            // Desencriptar credenciales
            var email = _cryptoRepository.Decrypt(emailEncrypted);
            var password = _cryptoRepository.Decrypt(passwordEncrypted);

            var requestLoginDTO = new RequestLoginDTO
            {
                Email = email,
                Password = password
            };

            return await _authRepository.LoginUserAsync(requestLoginDTO);
        }
        #endregion

        /// <summary>
        /// procesa solicitud de registro a través del gateway.
        /// flujo: recibe datos encriptados -> desencripta campos sensibles -> delega a AuthRepository -> retorna tokens
        /// </summary>
        /// <param name="cryptoDto">dto con datos de registro encriptados</param>
        /// <param name="cancellationToken">token de cancelación</param>
        /// <returns>tokens de acceso y refresh del usuario registrado</returns>
        #region register
        public async Task<ResponseLoginDTO> AuthRegisterAsync(
            RequestCryptoRegisterDTO cryptoDto, 
            CancellationToken cancellationToken = default)
        {
            // desencriptar campos sensibles
            var email = _cryptoRepository.Decrypt(cryptoDto.EmailEncrypted);
            var password = _cryptoRepository.Decrypt(cryptoDto.PasswordEncrypted);
            var confirmPassword = _cryptoRepository.Decrypt(cryptoDto.ConfirmPasswordEncrypted);
            var phone = !string.IsNullOrEmpty(cryptoDto.PhoneEncrypted) 
                ? _cryptoRepository.Decrypt(cryptoDto.PhoneEncrypted) 
                : null;

            var registerDto = new RegisterUserDTO
            {
                FirstName = cryptoDto.FirstName,
                LastName = cryptoDto.LastName,
                Email = email,
                Password = password,
                ConfirmPassword = confirmPassword,
                Phone = phone
            };

            return await _authRepository.RegisterUserAsync(registerDto);
        }
        #endregion

        /// <summary>
        /// procesa solicitud de renovación de token a través del gateway.
        /// flujo: recibe refresh token encriptado -> desencripta -> delega a AuthRepository -> retorna nuevos tokens
        /// </summary>
        /// <param name="refreshTokenEncrypted">refresh token encriptado</param>
        /// <param name="cancellationToken">token de cancelación</param>
        /// <returns>nuevo par de tokens (access y refresh)</returns>
        #region refresh
        public async Task<ResponseLoginDTO> AuthRefreshAsync(
            string refreshTokenEncrypted, 
            CancellationToken cancellationToken = default)
        {
            // desencriptar refresh token
            var refreshToken = _cryptoRepository.Decrypt(refreshTokenEncrypted);
            
            return await _authRepository.RefreshTokenAsync(refreshToken);
        }
        #endregion

        /// <summary>
        /// procesa solicitud de logout a través del gateway.
        /// flujo: recibe userId y accessToken -> delega a AuthRepository -> revoca sesión actual
        /// </summary>
        /// <param name="userId">id del usuario</param>
        /// <param name="accessToken">token de acceso actual</param>
        /// <param name="cancellationToken">token de cancelación</param>
        #region logout
        public async Task AuthLogoutAsync(
            int userId, 
            string accessToken, 
            CancellationToken cancellationToken = default)
        {
            await _authRepository.LogoutAsync(userId, accessToken);
        }
        #endregion

        /// <summary>
        /// procesa solicitud de logout global a través del gateway.
        /// flujo: recibe userId -> delega a AuthRepository -> revoca todas las sesiones del usuario
        /// </summary>
        /// <param name="userId">id del usuario</param>
        /// <param name="cancellationToken">token de cancelación</param>
        #region logout all
        public async Task AuthLogoutAllAsync(
            int userId, 
            CancellationToken cancellationToken = default)
        {
            _logger.LogDebug("[Gateway] Processing auth_logout_all for user {UserId}", userId);
            await _authRepository.RevokeAllUserSessionsAsync(userId);
        }

        public async Task<SessionInformationResponseDTO> AuthSessionInfoAsync(
            int userId, 
            CancellationToken cancellationToken = default)
        {
            _logger.LogDebug("[Gateway] Processing auth_session_info for user {UserId}", userId);

            var sessionInfo = await _authRepository.GetSessionInformationAsync(userId);

            return new SessionInformationResponseDTO
            {
                FirstName = sessionInfo.FirstName,
                LastName = sessionInfo.LastName,
                Email = _cryptoRepository.Encrypt(sessionInfo.Email),
                Phone = _cryptoRepository.Encrypt(sessionInfo.Phone),
                CreatedAt = _cryptoRepository.Encrypt(sessionInfo.CreatedAt.ToString("yyyy-MM-dd HH:mm:ss"))
            };
        }
        #endregion

        /// <summary>
        /// consulta logs de auditoría con filtros de búsqueda.
        /// flujo: recibe dto con filtros -> delega a AuditLogRepository -> retorna lista de logs
        /// </summary>
        /// <param name="requestDto">dto con filtros de búsqueda</param>
        /// <param name="cancellationToken">token de cancelación</param>
        /// <returns>lista de logs de auditoría</returns>
        #region consultar logs de auditoría
        public async Task<IEnumerable<ResponseAuditLogDTO>> GetAuditLogsAsync(
            RequestAuditLogDTO requestDto,
            CancellationToken cancellationToken = default)
        {
            _logger.LogDebug("[Gateway] Processing audit_logs_get for user {UserId}", requestDto.UserId);
            return await _auditLogRepository.GetAuditLogsAsync(requestDto);
        }
        #endregion
    }
}
