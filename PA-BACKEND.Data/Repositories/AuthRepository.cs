using Npgsql;
using NpgsqlTypes;
using BCrypt.Net;
using Dapper;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Http;
using System.Data;
// dtos
using PA_BACKEND.DTOs.Auth;
using PA_BACKEND.DTOs.AuditLog;
using PA_BACKEND.DTOs.Common;
// interfaces
using PA_BACKEND.Data.Interface;

namespace PA_BACKEND.Data.Repositories
{
    /// <summary>
    /// implementación del repositorio de autenticación.
    /// contiene la lógica de autenticación y generación de tokens.
    /// </summary>
    public class AuthRepository : IAuthRepository
    {
        private readonly NpgsqlConnection _connection;
        private readonly PostgreSQLConfiguration _configuration;
        private readonly IConfiguration _appConfiguration;
        private readonly ITokenRepository _tokenRepository;
        private readonly IAuditLogRepository _auditLogRepository;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly bool _isDevelopment;

        public AuthRepository(PostgreSQLConfiguration configuration, IConfiguration appConfiguration, ITokenRepository tokenRepository, IAuditLogRepository auditLogRepository, IHttpContextAccessor httpContextAccessor)
        {
            _configuration = configuration;
            _appConfiguration = appConfiguration;
            _tokenRepository = tokenRepository;
            _auditLogRepository = auditLogRepository;
            _httpContextAccessor = httpContextAccessor;
            _connection = new NpgsqlConnection(configuration.GetConnection().ConnectionString);
            _isDevelopment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") == "Development";
        }

        // obtiene la dirección ip del cliente desde el http context
        #region obtener ip del cliente
        private string GetClientIpAddress()
        {
            var context = _httpContextAccessor.HttpContext;
            if (context == null) return "unknown";
            
            var ip = context.Request.Headers["X-Forwarded-For"].FirstOrDefault();
            if (!string.IsNullOrEmpty(ip))
            {
                // Tomar solo la primera IP de la lista separada por comas
                ip = ip.Split(',')[0].Trim();
            }
            else
            {
                ip = context.Connection.RemoteIpAddress?.ToString();
            }
            
            // Si es IPv6 localhost, convertir a IPv4
            if (ip == "::1" || ip == "::1/128" || ip == "0:0:0:0:0:0:0:1")
            {
                ip = "127.0.0.1";
            }
            
            return ip ?? "unknown";
        }
        #endregion

        protected NpgsqlConnection GetConnection()
            => new NpgsqlConnection(_configuration.GetConnection().ConnectionString);

        /// <summary>
        /// normaliza el correo electrónico (trim y minúsculas).
        /// flujo: elimina espacios -> convierte a minúsculas -> retorna string limpio
        /// </summary>
        /// <param name="email">correo electrónico a normalizar</param>
        /// <returns>correo normalizado en minúsculas sin espacios</returns>
        #region normalizar email
        private string NormalizeEmail(string email)
            => email?.Trim().ToLowerInvariant() ?? string.Empty;
        #endregion

        /// <summary>
        /// registra un nuevo usuario (adoptante) en la base de datos.
        /// flujo: valida datos -> hashea contraseña -> crea usuario -> genera tokens -> retorna respuesta
        /// </summary>
        /// <param name="registerUserDTO">datos del nuevo usuario</param>
        /// <returns>tokens de acceso y refresh del usuario registrado</returns>
        #region registrar usuario
        public async Task<ResponseLoginDTO> RegisterUserAsync(RegisterUserDTO registerUserDTO)
        {
            if (registerUserDTO == null)
                throw new ArgumentNullException(nameof(registerUserDTO));

            if (string.IsNullOrWhiteSpace(registerUserDTO.Email) ||
                string.IsNullOrWhiteSpace(registerUserDTO.Password) ||
                string.IsNullOrWhiteSpace(registerUserDTO.FirstName) ||
                string.IsNullOrWhiteSpace(registerUserDTO.LastName))
                throw new ArgumentException("Campos requeridos");

            // variables para datos entre bloques
            int userId = 0;
            string? accessToken = null;
            string? refreshToken = null;
            string clientIp = GetClientIpAddress();

            try
            {
                var normalizedEmail = NormalizeEmail(registerUserDTO.Email);
                string hashedPassword = BCrypt.Net.BCrypt.HashPassword(registerUserDTO.Password);
                refreshToken = _tokenRepository.GenerateRefreshToken();

                using var connection = GetConnection();
                await connection.OpenAsync();

                using var transaction = await connection.BeginTransactionAsync();
                try
                {
                    (int UserId, string EmailHash) dbResult;

                    try
                    {                        
                        dbResult = await connection.QueryFirstOrDefaultAsync<(int UserId, string EmailHash)>(
                            "select * from public.fun_create_user(@p_first_name::varchar, @p_last_name::varchar, @p_email::varchar, @p_password_hash::varchar, @p_role_id::integer, @p_phone::varchar)",
                        new {
                            p_first_name = registerUserDTO.FirstName.Trim(),
                            p_last_name = registerUserDTO.LastName.Trim(),
                            p_email = normalizedEmail,
                            p_password_hash = hashedPassword,
                            p_role_id = 2,
                            p_phone = registerUserDTO.Phone?.Trim()
                        },
                        transaction
                    );
                    }
                    catch (PostgresException ex) when (ex.MessageText.Contains("Ya existe un usuario con ese email"))
                    {
                        // captura el error de duplicado que lanza la función SQL
                        throw new InvalidOperationException(SecureMessages.UserAlreadyExists);
                    }

                    if (dbResult.UserId <= 0)
                        throw new InvalidOperationException("No se pudo registrar el usuario.");

                    userId = dbResult.UserId;

                    await StoreRefreshTokenAsync(userId, refreshToken, connection, transaction);

                    accessToken = _tokenRepository.GenerateAccessToken(
                        userId,
                        "ADOPTANTE",
                        _tokenRepository.ExtractTokenId(refreshToken)
                    );

                    await transaction.CommitAsync();
                }
                catch
                {
                    await transaction.RollbackAsync();
                    throw;
                }
            }
            catch (Exception ex) when (ex is not ArgumentException && ex is not InvalidOperationException)
            {
                throw new InvalidOperationException(SecureMessages.InternalServerError);
            }

            // log de auditoría fuera de la transacción
            await _auditLogRepository.InsertAuditLogAsync(new InsertAuditLogDTO
            {
                UserId = userId,
                Action = "REGISTER_SUCCESS",
                EntityType = "users",
                EntityId = userId,
                IpAddress = clientIp
            });

            return new ResponseLoginDTO {
                AccessToken  = accessToken!,
                RefreshToken = refreshToken!
            };
        }
        #endregion

        /// <summary>
        /// login de usuario.
        /// flujo: valida credenciales -> verifica usuario -> revoca tokens antiguos -> genera nuevos tokens
        /// </summary>
        /// <param name="requestLoginDTO">credenciales de login</param>
        /// <returns>tokens de acceso y refresh del usuario autenticado</returns>
        #region login
        public async Task<ResponseLoginDTO> LoginUserAsync(RequestLoginDTO requestLoginDTO)
        {
            if (requestLoginDTO == null)
                throw new ArgumentNullException(nameof(requestLoginDTO));

            if (string.IsNullOrWhiteSpace(requestLoginDTO.Email) ||
                string.IsNullOrWhiteSpace(requestLoginDTO.Password))
                throw new ArgumentException("Email y contraseña requeridos");

            // variables para datos entre bloques
            int userId = 0;
            string? accessToken = null;
            string? refreshToken = null;
            string clientIp = GetClientIpAddress();
            string action = "LOGIN_FAILED";

            try
            {
                var normalizedEmail = NormalizeEmail(requestLoginDTO.Email);

                using var connection = GetConnection();
                await connection.OpenAsync();

                using var transaction = await connection.BeginTransactionAsync();
                try
                {
                    var result = await connection.QueryFirstOrDefaultAsync<dynamic>(
                        "select * from public.fun_get_user_for_login(@Email::varchar)",
                        new { Email = normalizedEmail },
                        transaction
                    );

                    // usuario no encontrado
                    if (result == null)
                    {
                        userId = 0;
                    }
                    else
                    {
                        userId = (int)result.user_id;

                        bool isPasswordValid = BCrypt.Net.BCrypt.Verify(requestLoginDTO.Password, (string)result.password_hash);
                        if (!isPasswordValid)
                        {
                            // contraseña incorrecta - mantener userId para log
                        }
                        else if (!(bool)result.is_active)
                        {
                            // usuario inactivo - mantener userId para log
                        }
                        else
                        {
                            // login exitoso
                            await RevokeAllUserRefreshTokensAsync(userId, connection, transaction);

                            refreshToken = _tokenRepository.GenerateRefreshToken();
                            await StoreRefreshTokenAsync(userId, refreshToken, connection, transaction);

                            accessToken = _tokenRepository.GenerateAccessToken(
                                userId,
                                (string)result.role_name,
                                _tokenRepository.ExtractTokenId(refreshToken)
                            );

                            await transaction.CommitAsync();
                            action = "LOGIN_SUCCESS";
                        }
                    }

                    // si no fue exitoso, cerrar transacción sin cambios
                    if (action != "LOGIN_SUCCESS")
                    {
                        await transaction.CommitAsync(); // commit vacío para cerrar la transacción limpiamente
                    }
                }
                catch
                {
                    await transaction.RollbackAsync();
                    throw;
                }
            }
            catch (Exception ex) when (ex is not ArgumentException && ex is not InvalidOperationException)
            {
                throw new InvalidOperationException(SecureMessages.InternalServerError);
            }

            // log de auditoría fuera de la transacción (siempre se ejecuta)
            await _auditLogRepository.InsertAuditLogAsync(new InsertAuditLogDTO
            {
                UserId = userId,
                Action = action,
                EntityType = "users",
                EntityId = userId,
                IpAddress = clientIp
            });

            // lanzar excepción después de hacer el log
            if (action == "LOGIN_FAILED")
            {
                throw new InvalidOperationException(SecureMessages.InvalidCredentials);
            }

            return new ResponseLoginDTO {
                AccessToken  = accessToken!,
                RefreshToken = refreshToken!
            };
        }
        #endregion

        /// <summary>
        /// almacena el refresh token en la base de datos.
        /// flujo: valida parámetros -> inserta token con expiración -> retorna sin error
        /// </summary>
        /// <param name="userId">id del usuario</param>
        /// <param name="refreshToken">token a almacenar</param>
        /// <param name="connection">conexión a base de datos</param>
        /// <param name="transaction">transacción opcional</param>
        #region almacenar refresh token
        private async Task StoreRefreshTokenAsync(int userId, string refreshToken, NpgsqlConnection connection, NpgsqlTransaction? transaction = null)
        {
            if (userId <= 0 || string.IsNullOrWhiteSpace(refreshToken))
                throw new ArgumentException("Parámetros inválidos");

            var tokenId    = _tokenRepository.ExtractTokenId(refreshToken);
            var randomValue = _tokenRepository.ExtractRandomValue(refreshToken);

            if (!Guid.TryParse(tokenId, out var tokenIdGuid) || string.IsNullOrWhiteSpace(randomValue))
                throw new ArgumentException("Formato de token inválido");

            string hashedRandomValue = BCrypt.Net.BCrypt.HashPassword(randomValue);

            await connection.ExecuteAsync(
                "select * from public.fun_insert_refresh_token(@p_user_id, @p_token_id, @p_token_hash, @p_expires_at)",
                new {
                    p_user_id    = userId,
                    p_token_id   = tokenIdGuid,
                    p_token_hash = hashedRandomValue,
                    p_expires_at = DateTime.UtcNow.AddDays(
                        double.TryParse(
                            _appConfiguration["RefreshToken:ExpirationDays"], 
                            out double days
                        ) && days > 0 ? days : 1
                    )
                },
                transaction
            );
        }
        #endregion

        /// <summary>
        /// renueva los tokens de acceso usando un refresh token válido.
        /// flujo: valida refresh token -> revoca token anterior -> genera nuevo par de tokens -> retorna respuesta
        /// </summary>
        /// <param name="refreshToken">refresh token a renovar</param>
        /// <returns>nuevo par de tokens (access y refresh)</returns>
        #region renovar tokens
        public async Task<ResponseLoginDTO> RefreshTokenAsync(string refreshToken)
        {
            if (string.IsNullOrWhiteSpace(refreshToken))
                throw new ArgumentException("Refresh token requerido");

            var tokenId = _tokenRepository.ExtractTokenId(refreshToken);
            var randomValue = _tokenRepository.ExtractRandomValue(refreshToken);

            if (!Guid.TryParse(tokenId, out var tokenIdGuid) || string.IsNullOrWhiteSpace(randomValue))
                throw new ArgumentException("Formato de token inválido");

            // variables para log en caso de fallo
            int userId = 0;
            string clientIp = GetClientIpAddress();
            bool refreshFailed = false;

            using var connection = GetConnection();
            await connection.OpenAsync();

            using var transaction = await connection.BeginTransactionAsync();
            try
            {
                var tokenRecord = await connection.QueryFirstOrDefaultAsync<dynamic>(
                    "select * from public.fun_get_refresh_token_by_token_id(@p_token_id)",
                    new { p_token_id = tokenIdGuid },
                    transaction
                );

                if (tokenRecord == null)
                    throw new InvalidOperationException(SecureMessages.InvalidToken);

                // valida revocación antes de validar el hash
                if ((bool)tokenRecord.is_revoked)
                    throw new InvalidOperationException(SecureMessages.InvalidToken);

                // valida expiración
                if (DateTime.UtcNow > Convert.ToDateTime(tokenRecord.expires_at).ToUniversalTime())
                    throw new InvalidOperationException(SecureMessages.TokenExpired);

                // valida hash
                bool isValidHash = BCrypt.Net.BCrypt.Verify(randomValue, (string)tokenRecord.token_hash);
                if (!isValidHash)
                    throw new InvalidOperationException(SecureMessages.InvalidToken);

                userId = (int)tokenRecord.user_id;

                // revoca el token usado
                await connection.ExecuteAsync(
                    "select * from public.fun_revoke_refresh_token(@p_token_id)",
                    new { p_token_id = tokenIdGuid },
                    transaction
                );

                // enforce límite de dispositivos
                await RevokeAllUserRefreshTokensAsync(userId, connection, transaction);

                string newRefreshToken = _tokenRepository.GenerateRefreshToken();
                await StoreRefreshTokenAsync(userId, newRefreshToken, connection, transaction);

                string newAccessToken = _tokenRepository.GenerateAccessToken(
                    userId,
                    (string)tokenRecord.role_name,
                    _tokenRepository.ExtractTokenId(newRefreshToken)
                );

                await transaction.CommitAsync();

                return new ResponseLoginDTO {
                    AccessToken  = newAccessToken,
                    RefreshToken = newRefreshToken
                };
            }
            catch (Exception ex) when (ex is not ArgumentException && ex is not InvalidOperationException)
            {
                await transaction.RollbackAsync();
                refreshFailed = true;
                throw new InvalidOperationException(SecureMessages.InternalServerError);
            }
            catch
            {
                await transaction.RollbackAsync();
                refreshFailed = true;
                throw;
            }
            finally
            {
                // solo loguear en caso de fallo
                if (refreshFailed)
                {
                    await _auditLogRepository.InsertAuditLogAsync(new InsertAuditLogDTO
                    {
                        UserId = userId,
                        Action = "REFRESH_TOKEN_FAILED",
                        EntityType = "users",
                        EntityId = userId,
                        IpAddress = clientIp
                    });
                }
            }
        }
        #endregion

        /// <summary>
        /// cierra la sesión de un usuario específico.
        /// flujo: valida parámetros -> extrae jti del access token -> marca refresh token como revocado -> confirma logout
        /// </summary>
        /// <param name="userId">id del usuario</param>
        /// <param name="accessToken">token de acceso actual</param>
        #region logout
        public async Task LogoutAsync(int userId, string accessToken)
        {
            if (userId <= 0)
                throw new ArgumentException("ID de usuario inválido");

            if (string.IsNullOrWhiteSpace(accessToken))
                throw new ArgumentException("Access token requerido");

            string clientIp = GetClientIpAddress();

            try
            {
                // extrae jti y expiración del jwt
                var jti       = _tokenRepository.ExtractJti(accessToken);
                var expiresAt = _tokenRepository.ExtractExpiration(accessToken);

                if (!Guid.TryParse(jti, out var jtiGuid))
                    throw new ArgumentException("Token inválido");

                using var connection = GetConnection();
                await connection.OpenAsync();

                using var transaction = await connection.BeginTransactionAsync();
                try
                {
                    await connection.ExecuteAsync(
                        "select public.fun_logout(@p_user_id, @p_jti, @p_expires_at)",
                        new {
                            p_user_id = userId,
                            p_jti = jtiGuid,
                            p_expires_at = expiresAt.ToUniversalTime()
                        },
                        transaction
                    );

                    await transaction.CommitAsync();
                }
                catch
                {
                    await transaction.RollbackAsync();
                    throw;
                }
            }
            catch (Exception ex) when (ex is not ArgumentException && ex is not InvalidOperationException)
            {
                throw new InvalidOperationException(SecureMessages.InternalServerError);
            }

            // log de auditoría fuera de la transacción
            await _auditLogRepository.InsertAuditLogAsync(new InsertAuditLogDTO
            {
                UserId = userId,
                Action = "LOGOUT_SUCCESS",
                EntityType = "users",
                EntityId = userId,
                IpAddress = clientIp
            });
        }
        #endregion

        /// <summary>
        /// revoca tokens excedentes — conserva los p_max_devices más recientes.
        /// flujo: ejecuta función de base de datos -> mantiene tokens más recientes -> revoca antiguos
        /// </summary>
        /// <param name="userId">id del usuario</param>
        /// <param name="connection">conexión a base de datos</param>
        /// <param name="transaction">transacción actual</param>
        #region gestionar refresh tokens
        private async Task RevokeAllUserRefreshTokensAsync(int userId, NpgsqlConnection connection, NpgsqlTransaction transaction)
        {
            if (userId <= 0)
                return;

            var revokedCount = await connection.QueryFirstOrDefaultAsync<int>(
                "select * from public.fun_enforce_refresh_token_limit(@p_user_id, @p_max_devices)",
                new {
                    p_user_id = userId,
                    p_max_devices = 2
                },
                transaction
            );

            if (revokedCount > 0); // tokens revocados
        }
        #endregion

        /// <summary>
        /// revoca todas las sesiones de un usuario (logout global).
        /// flujo: valida id -> conecta a base de datos -> revoca todos los refresh tokens -> confirma operación
        /// </summary>
        /// <param name="userId">id del usuario</param>
        #region logout global
        public async Task RevokeAllUserSessionsAsync(int userId)
        {
            if (userId <= 0)
                throw new ArgumentException("ID de usuario inválido");

            string clientIp = GetClientIpAddress();

            try
            {
                using var connection = GetConnection();
                await connection.OpenAsync();

                using var transaction = await connection.BeginTransactionAsync();
                try
                {
                    var revokedCount = await connection.QueryFirstOrDefaultAsync<int>(
                        "select * from public.fun_enforce_refresh_token_limit(@p_user_id, @p_max_devices)",
                        new {
                            p_user_id = userId,
                            p_max_devices = 0 // 0 = revocar todos
                        },
                        transaction
                    );
                    await transaction.CommitAsync();

                    if (revokedCount > 0); // sesiones revocadas
                }
                catch
                {
                    await transaction.RollbackAsync();
                    throw;
                }
            }
            catch (Exception ex) when (ex is not ArgumentException)
            {
                throw new InvalidOperationException(SecureMessages.InternalServerError);
            }

            // log de auditoría fuera de la transacción
            await _auditLogRepository.InsertAuditLogAsync(new InsertAuditLogDTO
            {
                UserId = userId,
                Action = "LOGOUT_ALL_SUCCESS",
                EntityType = "users",
                EntityId = userId,
                IpAddress = clientIp
            });
        }
        #endregion

        /// <summary>
        /// obtiene información de sesión del usuario.
        /// flujo: valida id -> conecta a base de datos -> ejecuta función -> mapea resultado
        /// </summary>
        /// <param name="userId">id del usuario</param>
        /// <returns>información de sesión del usuario</returns>
        #region obtener información de sesión
        public async Task<SessionInformationDTO> GetSessionInformationAsync(int userId)
        {
            if (userId <= 0)
                throw new ArgumentException("ID de usuario inválido");

            string clientIp = GetClientIpAddress();

            try
            {
                using var connection = GetConnection();
                await connection.OpenAsync();

                var parameters = new DynamicParameters();
                parameters.Add("p_user_id", userId, DbType.Int32);

                var result = await connection.QueryFirstOrDefaultAsync<SessionInformationDTO>(
                    "SELECT first_name AS FirstName, last_name AS LastName, email AS Email, phone AS Phone, created_at AS CreatedAt FROM public.fun_obtener_informacion_sesion_usuario(@p_user_id)",
                    parameters
                );

                if (result == null)
                    throw new InvalidOperationException("Usuario no encontrado");

                return result;
            }
            catch (Exception ex) when (ex is not ArgumentException && ex is not InvalidOperationException)
            {
                throw new InvalidOperationException(SecureMessages.InternalServerError);
            }
            finally
            {
                // log de auditoría (lectura de información de sesión)
                await _auditLogRepository.InsertAuditLogAsync(new InsertAuditLogDTO
                {
                    UserId = userId,
                    Action = "SESSION_INFO_ACCESSED",
                    EntityType = "users",
                    EntityId = userId,
                    IpAddress = clientIp
                });
            }
        }
        #endregion
    }
}