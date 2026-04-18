using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
// dtos
using PA_BACKEND.DTOs.Auth;
using PA_BACKEND.DTOs.AuditLog;
using PA_BACKEND.DTOs.Common;
// interfaces
using PA_BACKEND.Data.Interface;

namespace PA_BACKEND.Controllers
{
    /// <summary>
    /// gateway unificado para todas las operaciones encriptadas.
    /// todos los requests del frontend pasan por aquí.
    /// </summary>
    [ApiController]
    [Route("api/[controller]")]
    public class GatewayController : ControllerBase
    {
        private readonly IGatewayRepository _gatewayRepository;
        private readonly ICryptoRepository _cryptoRepository;

        public GatewayController(
            IGatewayRepository gatewayRepository,
            ICryptoRepository cryptoRepository)
        {
            _gatewayRepository = gatewayRepository;
            _cryptoRepository = cryptoRepository;
        }

        /// <summary>
        /// endpoint único del gateway.
        /// flujo: recibe todas las peticiones encriptadas y las enruta al servicio correspondiente.
        /// </summary>
        /// <param name="request">dto con endpoint, timestamp y datos encriptados</param>
        /// <returns>respuesta procesada según el endpoint solicitado</returns>
        #region proceso de solicitud
        [HttpPost]
        public async Task<IActionResult> Process([FromBody] GatewayRequestDTO request)
        {
            try
            {
                // 1. validar estructura del request
                if (request == null || string.IsNullOrWhiteSpace(request.Endpoint))
                {
                    return BadRequest(ResponseAPIHelper.Fail(
                        "Endpoint es requerido", 
                        ErrorCodes.ValidationError));
                }

                // 2. validar que el endpoint esté registrado
                var route = GatewayRoutes.GetRoute(request.Endpoint);
                if (route == null)
                {
                    return BadRequest(ResponseAPIHelper.Fail(
                        "Endpoint no encontrado", 
                        ErrorCodes.ValidationError));
                }

                // 3. validar timestamp anti-replay (siempre requerido)
                if (string.IsNullOrEmpty(request.Exp))
                {
                    return BadRequest(ResponseAPIHelper.Fail(
                        "Timestamp requerido", 
                        ErrorCodes.ValidationError));
                }

                var expDecrypted = _cryptoRepository.Decrypt(request.Exp);
                _cryptoRepository.ValidateTimestamp(expDecrypted, maxMinutes: 5);

                // 4. verificar autorización si el endpoint lo requiere
                if (route.RequiresAuth)
                {
                    var authResult = ValidateAuthorization();
                    if (authResult != null) return authResult;
                }

                // 5. enrutar al handler correspondiente
                return await RouteRequest(request, route);
            }
            catch (ArgumentException)
            {
                return BadRequest(ResponseAPIHelper.Fail(SecureMessages.InvalidRequest, ErrorCodes.ValidationError));
            }
            catch (InvalidOperationException)
            {
                return BadRequest(ResponseAPIHelper.Fail(SecureMessages.InvalidRequest, ErrorCodes.AuthenticationFailed));
            }
            catch (CryptographicException)
            {
                return BadRequest(ResponseAPIHelper.Fail(
                    "Error de desencriptación", 
                    ErrorCodes.AuthenticationFailed));
            }
            catch (Exception)
            {
                return StatusCode(500, ResponseAPIHelper.Fail(
                    SecureMessages.InternalServerError, 
                    ErrorCodes.InternalError));
            }
        }
        #endregion

        /// <summary>
        /// valida el header de autorización y extrae el userid.
        /// flujo: verifica token jwt -> extrae claim nameidentifier -> valida formato numérico
        /// </summary>
        /// <returns>null si autorización válida, IActionResult con error si inválida</returns>
        #region validacion de autorizacion
        private IActionResult? ValidateAuthorization()
        {
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier);
            
            if (userIdClaim == null || !int.TryParse(userIdClaim.Value, out _))
            {
                return Unauthorized(ResponseAPIHelper.Fail(
                    SecureMessages.InvalidToken, 
                    ErrorCodes.TokenInvalid));
            }

            return null; // autorización válida
        }
        #endregion

        /// <summary>
        /// enruta el request al handler específico según el endpoint.
        /// flujo: identifica ruta por key -> ejecuta handler correspondiente -> retorna resultado
        /// </summary>
        /// <param name="request">request original del gateway</param>
        /// <param name="route">definición de ruta encontrada</param>
        /// <returns>respuesta del handler específico</returns>
        #region enrutamiento
        private async Task<IActionResult> RouteRequest(GatewayRequestDTO request, GatewayRoutes.RouteDefinition route)
        {
            switch (route.Key.ToLower())
            {
                // auth
                case "auth_login":
                    return await HandleAuthLogin(request.Data);
                    
                case "auth_register":
                    return await HandleAuthRegister(request.Data);
                    
                case "auth_refresh":
                    return await HandleAuthRefresh(request.Data);
                    
                case "auth_logout":
                    return await HandleAuthLogout(request.Data);
                    
                case "auth_logout_all":
                    return await HandleAuthLogoutAll();
                    
                case "auth_session_info":
                    return await HandleAuthSessionInfo();
                    
                case "audit_logs_get":
                    return await HandleAuditLogsGet(request.Data);
                    
                default:
                    return StatusCode(500, ResponseAPIHelper.Fail(
                        "Configuración de ruta incompleta", 
                        ErrorCodes.InternalError));
            }
        }
        #endregion

        /// <summary>
        /// procesa login de usuario a través del gateway.
        /// flujo: extrae email y password encriptados -> desencripta -> valida timestamp -> delega a gateway service -> retorna tokens
        /// </summary>
        /// <param name="data">json element con credenciales encriptadas</param>
        /// <returns>respuesta con tokens de acceso o error</returns>
        #region gestion de autenticación
        private async Task<IActionResult> HandleAuthLogin(JsonElement data)
        {
            var emailEncrypted = data.GetProperty("email").GetString();
            var passwordEncrypted = data.GetProperty("password").GetString();

            if (string.IsNullOrEmpty(emailEncrypted) || string.IsNullOrEmpty(passwordEncrypted))
            {
                return BadRequest(ResponseAPIHelper.Fail(
                    "Credenciales requeridas", 
                    ErrorCodes.ValidationError));
            }

            var result = await _gatewayRepository.AuthLoginAsync(emailEncrypted, passwordEncrypted);
            return Ok(ResponseAPIHelper.SuccessResult(result, SecureMessages.LoginSuccess));
        }
        #endregion

        /// <summary>
        /// procesa registro de usuario a través del gateway.
        /// flujo: deserializa dto de registro encriptado -> delega a gateway service -> retorna tokens
        /// </summary>
        /// <param name="data">json element con datos de registro encriptados</param>
        /// <returns>respuesta con tokens de acceso o error</returns>
        #region gestion de registro
        private async Task<IActionResult> HandleAuthRegister(JsonElement data)
        {
            var cryptoDto = JsonSerializer.Deserialize<RequestCryptoRegisterDTO>(data);
            if (cryptoDto == null)
            {
                return BadRequest(ResponseAPIHelper.Fail(
                    "Datos inválidos", 
                    ErrorCodes.ValidationError));
            }

            var result = await _gatewayRepository.AuthRegisterAsync(cryptoDto);
            return Ok(ResponseAPIHelper.SuccessResult(result, SecureMessages.RegistrationSuccess));
        }
        #endregion

        /// <summary>
        /// procesa renovación de token a través del gateway.
        /// flujo: extrae refresh token encriptado -> delega a gateway service -> retorna nuevos tokens
        /// </summary>
        /// <param name="data">json element con refresh token encriptado</param>
        /// <returns>respuesta con nuevos tokens o error</returns>
        #region gestion de renovación de token
        private async Task<IActionResult> HandleAuthRefresh(JsonElement data)
        {
            var refreshTokenEncrypted = data.GetProperty("refreshToken").GetString();
            
            if (string.IsNullOrEmpty(refreshTokenEncrypted))
            {
                return BadRequest(ResponseAPIHelper.Fail(
                    "Token requerido", 
                    ErrorCodes.ValidationError));
            }

            var result = await _gatewayRepository.AuthRefreshAsync(refreshTokenEncrypted);
            return Ok(ResponseAPIHelper.SuccessResult(result, SecureMessages.RefreshSuccess));
        }
        #endregion

        /// <summary>
        /// procesa logout de usuario a través del gateway.
        /// flujo: extrae userid del token jwt -> obtiene access token del header -> delega a gateway service
        /// </summary>
        /// <param name="data">json element (no utilizado en logout)</param>
        /// <returns>confirmación de cierre de sesión o error</returns>
        #region gestion de logout
        private async Task<IActionResult> HandleAuthLogout(JsonElement data)
        {
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier);
            var userId = int.Parse(userIdClaim!.Value);
            
            var accessToken = Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
            
            if (string.IsNullOrEmpty(accessToken))
            {
                return BadRequest(ResponseAPIHelper.Fail(
                    "Autorización requerida", 
                    ErrorCodes.ValidationError));
            }
            
            await _gatewayRepository.AuthLogoutAsync(userId, accessToken);
            return Ok(ResponseAPIHelper.Success(SecureMessages.SessionRevoked));
        }
        #endregion

        /// <summary>
        /// procesa logout en todos los dispositivos a través del gateway.
        /// flujo: extrae userid del token jwt -> delega a gateway service para revocar todas las sesiones
        /// </summary>
        /// <returns>confirmación de cierre de todas las sesiones o error</returns>
        #region gestion de logout todos los dispositivos
        private async Task<IActionResult> HandleAuthLogoutAll()
        {
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier);
            var userId = int.Parse(userIdClaim!.Value);
            
            await _gatewayRepository.AuthLogoutAllAsync(userId);
            return Ok(ResponseAPIHelper.Success(SecureMessages.SessionRevokedAll));
        }
        #endregion

        /// <summary>
        /// procesa solicitud de información de sesión a través del gateway.
        /// flujo: extrae userid del token jwt -> delega a gateway service -> retorna respuesta con datos encriptados
        /// </summary>
        /// <returns>información de sesión con datos sensibles encriptados</returns>
        #region gestion de información de sesión
        private async Task<IActionResult> HandleAuthSessionInfo()
        {
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier);
            var userId = int.Parse(userIdClaim!.Value);
            
            var result = await _gatewayRepository.AuthSessionInfoAsync(userId);
            return Ok(ResponseAPIHelper.SuccessResult(result, "Información de sesión obtenida"));
        }
        #endregion

        /// <summary>
        /// procesa consulta de logs de auditoría a través del gateway.
        /// flujo: deserializa dto con filtros -> delega a gateway service -> retorna lista de logs
        /// </summary>
        /// <param name="data">json element con filtros de búsqueda</param>
        /// <returns>lista de logs de auditoría</returns>
        #region gestion de logs de auditoría
        private async Task<IActionResult> HandleAuditLogsGet(JsonElement data)
        {
            // Debug logging
            Console.WriteLine($"[DEBUG] HandleAuditLogsGet - Raw data: {data}");
            
            // Los datos vienen en texto plano (no encriptados) - deserializar con CamelCase
            var jsonOptions = new JsonSerializerOptions
            {
                PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase
            };
            
            var requestDto = JsonSerializer.Deserialize<RequestAuditLogDTO>(data, jsonOptions);
            if (requestDto == null)
            {
                Console.WriteLine("[DEBUG] HandleAuditLogsGet - requestDto is null");
                return BadRequest(ResponseAPIHelper.Fail(
                    "Datos de búsqueda inválidos",
                    ErrorCodes.ValidationError));
            }

            // Debug logging
            Console.WriteLine($"[DEBUG] HandleAuditLogsGet - Deserialized DTO:");
            Console.WriteLine($"  Limit: {requestDto.Limit}");
            Console.WriteLine($"  Offset: {requestDto.Offset}");
            Console.WriteLine($"  Action: {requestDto.Action}");
            Console.WriteLine($"  UserId: {requestDto.UserId}");
            Console.WriteLine($"  IpAddress: {requestDto.IpAddress}");
            Console.WriteLine($"  DateFrom: {requestDto.DateFrom}");
            Console.WriteLine($"  DateTo: {requestDto.DateTo}");

            // validar límites
            if (requestDto.Limit <= 0) requestDto.Limit = 50;
            if (requestDto.Limit > 100) requestDto.Limit = 100;
            if (requestDto.Offset < 0) requestDto.Offset = 0;

            var result = await _gatewayRepository.GetAuditLogsAsync(requestDto);
            
            // Debug logging
            Console.WriteLine($"[DEBUG] HandleAuditLogsGet - Result count: {result?.Count() ?? 0}");
            
            return Ok(ResponseAPIHelper.SuccessResult(result, "Logs de auditoría consultados correctamente"));
        }
        #endregion
    }
}
