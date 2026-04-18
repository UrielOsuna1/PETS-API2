using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
// dtos
using PA_BACKEND.DTOs.Auth;
using PA_BACKEND.DTOs.Common;
// interfaces
using PA_BACKEND.Data.Interface;

namespace PA_BACKEND.Controllers
{
    /// <summary>
    /// controlador para operaciones de autenticación y gestión de usuarios.
    /// incluye endpoints para login, registro, refresh token y logout.
    /// </summary>
    [ApiController]
    [Route("api/[controller]")]
    [ApiExplorerSettings(IgnoreApi = true)]
    public class AuthController : ControllerBase
    {
        private readonly IAuthRepository _authRepository;
        private readonly ICryptoRepository _cryptoRepository;

        public AuthController(IAuthRepository authRepository, ICryptoRepository cryptoRepository)
        {
            _authRepository = authRepository;
            _cryptoRepository = cryptoRepository;
        }

        /// <summary>
        /// registra un nuevo usuario adoptante en el sistema.
        /// flujo: Recibe dto de registro -> valida datos -> delega a AuthRepository para crear usuario 
        /// -> retorna respuesta con tokens de autenticación o errores específicos
        /// </summary>
        /// <param name="registerUserDTO">datos del usuario a registrar</param>
        /// <returns>respuesta con tokens de acceso y refresh o mensaje de error</returns>
        #region registrar usuario (adoptante)
        [HttpPost("register-client")]
        public async Task<IActionResult> Register([FromBody] RegisterUserDTO registerUserDTO)
        {
            try
            {
                var result = await _authRepository.RegisterUserAsync(registerUserDTO);
                return Ok(ResponseAPIHelper.SuccessResult(result, SecureMessages.RegistrationSuccess));
            }
            catch (ArgumentException ex)
            {
                return BadRequest(ResponseAPIHelper.Fail(ex.Message, ErrorCodes.ValidationError));
            }
            catch (InvalidOperationException)
            {
                return BadRequest(ResponseAPIHelper.Fail(SecureMessages.UserAlreadyExists, ErrorCodes.UserExists));
            }
            catch (Exception)
            {
                return StatusCode(500, ResponseAPIHelper.Fail(SecureMessages.InternalServerError, ErrorCodes.InternalError));
            }
        }
        #endregion

        /// <summary>
        /// autentica un usuario mediante credenciales limpias.
        /// flujo: recibe dto limpio -> delega a AuthRepository para validación -> retorna tokens de sesión o errores
        /// </summary>
        /// <param name="request">dto con credenciales limpias</param>
        /// <returns>respuesta con tokens de acceso y refresh o mensaje de error</returns>
        #region login usuario
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] RequestLoginDTO request)
        {
            try
            {
                if (request == null)
                    return BadRequest(ResponseAPIHelper.Fail(SecureMessages.InvalidCredentials, ErrorCodes.ValidationError));

                if (string.IsNullOrEmpty(request.Email) || string.IsNullOrEmpty(request.Password))
                    return BadRequest(ResponseAPIHelper.Fail(SecureMessages.InvalidCredentials, ErrorCodes.ValidationError));
                    
                var result = await _authRepository.LoginUserAsync(request);
                return Ok(ResponseAPIHelper.SuccessResult(result, SecureMessages.LoginSuccess));
            }
            catch (ArgumentException ex)
            {
                return BadRequest(ResponseAPIHelper.Fail(ex.Message, ErrorCodes.ValidationError));
            }
            catch (InvalidOperationException)
            {
                return BadRequest(ResponseAPIHelper.Fail(SecureMessages.InvalidCredentials, ErrorCodes.AuthenticationFailed));
            }
            catch (Exception)
            {
                return StatusCode(500, ResponseAPIHelper.Fail(SecureMessages.InternalServerError, ErrorCodes.InternalError));
            }
        }
        #endregion
        
        /// <summary>
        /// renueva los tokens de acceso usando un refresh token válido.
        /// flujo: recibe refresh token -> valida existencia y vigencia -> genera nuevo par de tokens 
        /// -> invalida refresh token anterior -> retorna nuevos tokens de acceso
        /// </summary>
        /// <param name="requestRefreshTokenDTO">dto conteniendo el refresh token</param>
        /// <returns>nuevo par de tokens (access y refresh) o mensaje de error</returns>
        #region refresh token
        [HttpPost("refresh")]
        [Authorize]
        public async Task<IActionResult> RefreshToken([FromBody] RequestRefreshTokenDTO requestRefreshTokenDTO)
        {
            try
            {
                if (requestRefreshTokenDTO?.RefreshToken == null)
                    return BadRequest(ResponseAPIHelper.Fail(SecureMessages.InvalidToken, ErrorCodes.ValidationError));
                
                var result = await _authRepository.RefreshTokenAsync(requestRefreshTokenDTO.RefreshToken);
                return Ok(ResponseAPIHelper.SuccessResult(result, SecureMessages.RefreshSuccess));
            }
            catch (ArgumentException ex)
            {
                return BadRequest(ResponseAPIHelper.Fail(ex.Message, ErrorCodes.ValidationError));
            }
            catch (InvalidOperationException)
            {
                return BadRequest(ResponseAPIHelper.Fail(SecureMessages.InvalidToken, ErrorCodes.TokenInvalid));
            }
            catch (Exception)
            {
                return StatusCode(500, ResponseAPIHelper.Fail(SecureMessages.InternalServerError, ErrorCodes.InternalError));
            }
        }
        #endregion

        /// <summary>
        /// extrae y valida el userId del token JWT.
        /// flujo: busca claim nameidentifier -> intenta parsear a int -> retorna resultado
        /// </summary>
        /// <param name="userId">userId extraído</param>
        /// <returns>true si userId es válido, false si no</returns>
        #region obtener userid del token
        private bool TryGetUserId(out int userId)
        {
            userId = 0;
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier);
            
            if (userIdClaim == null || !int.TryParse(userIdClaim.Value ?? "", out userId))
            {
                return false;
            }
            
            return true;
        }
        #endregion

        /// <summary>
        /// cierra la sesión actual del usuario autenticado.
        /// flujo: extrae userid del token jwt -> obtiene access token del header 
        /// -> delega a AuthRepository para invalidar sesión específica -> retorna confirmación
        /// </summary>
        /// <returns>confirmación de cierre de sesión o mensaje de error</returns>
        #region logout usuario
        [HttpPost("logout")]
        [Authorize]
        public async Task<IActionResult> Logout()
        {
            try
            {
                if (!TryGetUserId(out var userId))
                {
                    return Unauthorized(ResponseAPIHelper.Fail(SecureMessages.InvalidToken, ErrorCodes.TokenInvalid));
                }

                var accessToken = Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
                await _authRepository.LogoutAsync(userId, accessToken);
                return Ok(ResponseAPIHelper.Success(SecureMessages.SessionRevoked));
            }
            catch (Exception)
            {
                return StatusCode(500, ResponseAPIHelper.Fail(SecureMessages.InternalServerError, ErrorCodes.InternalError));
            }
        }
        #endregion

        /// <summary>
        /// cierra todas las sesiones activas del usuario en todos los dispositivos.
        /// flujo: extrae userid del token jwt -> delega a AuthRepository para revocar todos los refresh tokens 
        /// del usuario -> invalida todas las sesiones activas -> retorna confirmación
        /// </summary>
        /// <returns>confirmación de cierre de todas las sesiones o mensaje de error</returns>
        #region logout todos los dispositivos
        [HttpPost("logout-all")]
        [Authorize]
        public async Task<IActionResult> LogoutAllDevices()
        {
            try
            {
                if (!TryGetUserId(out var userId))
                {
                    return Unauthorized(ResponseAPIHelper.Fail(SecureMessages.InvalidToken, ErrorCodes.TokenInvalid));
                }

                await _authRepository.RevokeAllUserSessionsAsync(userId);
                return Ok(ResponseAPIHelper.Success(SecureMessages.SessionRevokedAll));
            }
            catch (Exception)
            {
                return StatusCode(500, ResponseAPIHelper.Fail(SecureMessages.InternalServerError, ErrorCodes.InternalError));
            }
        }
        #endregion

        /// <summary>
        /// obtiene información de sesión del usuario autenticado.
        /// flujo: extrae userid del token jwt -> obtiene información -> encripta datos sensibles -> retorna respuesta
        /// </summary>
        /// <returns>información de sesión con datos sensibles encriptados</returns>
        #region obtener información de sesión
        [HttpPost("session-information")]
        [Authorize]
        public async Task<IActionResult> GetSessionInformation()
        {
            try
            {
                if (!TryGetUserId(out var userId))
                {
                    return Unauthorized(ResponseAPIHelper.Fail(SecureMessages.InvalidToken, ErrorCodes.TokenInvalid));
                }

                var sessionInfo = await _authRepository.GetSessionInformationAsync(userId);

                var response = new SessionInformationResponseDTO
                {
                    FirstName = sessionInfo.FirstName,
                    LastName = sessionInfo.LastName,
                    Email = _cryptoRepository.Encrypt(sessionInfo.Email),
                    Phone = _cryptoRepository.Encrypt(sessionInfo.Phone),
                    CreatedAt = _cryptoRepository.Encrypt(sessionInfo.CreatedAt.ToString("yyyy-MM-dd HH:mm:ss"))
                };

                return Ok(ResponseAPIHelper.SuccessResult(response, "Información de sesión obtenida"));
            }
            catch (ArgumentException)
            {
                return BadRequest(ResponseAPIHelper.Fail(SecureMessages.InvalidRequest, ErrorCodes.ValidationError));
            }
            catch (InvalidOperationException)
            {
                return NotFound(ResponseAPIHelper.Fail(SecureMessages.InvalidRequest, ErrorCodes.ValidationError));
            }
            catch (Exception)
            {
                return StatusCode(500, ResponseAPIHelper.Fail(SecureMessages.InternalServerError, ErrorCodes.InternalError));
            }
        }
        #endregion
    }
}
