using System.Security.Claims;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.Threading;
// dtos
using PA_BACKEND.DTOs.Common;
// interfaces
using PA_BACKEND.Data.Interface;

namespace PA_BACKEND.Data.Repositories
{
    /// <summary>
    /// implementación del repositorio de tokens jwt.
    /// contiene la lógica de generación, validación y extracción de información de tokens.
    /// </summary>
    public class TokenRepository : ITokenRepository
    {
        private readonly IConfiguration _config;
        private readonly bool _isDevelopment;

        public TokenRepository(IConfiguration config)
        {
            _config = config;
            _isDevelopment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") == "Development";
        }

        #region configuración
        // obtiene la clave jwt desde appsettings
        private string GetJwtKey() => _config["Jwt:Key"] ?? throw new InvalidOperationException(PA_BACKEND.DTOs.Common.SecureMessages.ConfigurationError);

        // obtiene el emisor jwt desde appsettings
        private string GetJwtIssuer() => _config["Jwt:Issuer"] ?? throw new InvalidOperationException(PA_BACKEND.DTOs.Common.SecureMessages.ConfigurationError);

        // obtiene la audiencia jwt desde appsettings
        private string GetJwtAudience() => _config["Jwt:Audience"] ?? throw new InvalidOperationException(PA_BACKEND.DTOs.Common.SecureMessages.ConfigurationError);

        // obtiene los minutos de expiración del jwt desde la configuración del sistema.
        private int GetJwtExpirationMinutes() => int.Parse(_config["Jwt:ExpirationMinutes"] ?? "60");
        #endregion

        /// <summary>
        /// genera un token de acceso jwt.
        /// flujo: valida configuración -> crea claims -> firma token -> retorna string jwt.
        /// </summary>
        /// <param name="userId">id del usuario.</param>
        /// <param name="roleName">nombre del rol.</param>
        /// <returns>token jwt generado.</returns>
        #region generar access token
        public string GenerateAccessToken(int userId, string roleName)
        {
            return GenerateAccessToken(userId, roleName, Guid.NewGuid().ToString());
        }
        #endregion

        /// <summary>
        /// genera un token de acceso jwt con id específico.
        /// flujo: valida configuración y parámetros -> crea claims -> firma token -> retorna string jwt.
        /// </summary>
        /// <param name="userId">id del usuario.</param>
        /// <param name="roleName">nombre del rol.</param>
        /// <param name="tokenId">identificador único del token.</param>
        /// <returns>token jwt generado.</returns>
        #region generar access token con token id
        public string GenerateAccessToken(int userId, string roleName, string tokenId)
        {
            // validar configuración jwt antes de generar token
            ValidateJwtConfiguration();

            // validación de parámetros críticos
            if (userId <= 0)
                throw new ArgumentException("ID de usuario inválido");
            
            if (string.IsNullOrWhiteSpace(roleName))
                throw new ArgumentException("Nombre de rol inválido");

            if (string.IsNullOrWhiteSpace(tokenId))
                throw new ArgumentException("Token ID inválido");

            // creación de claims para el token
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
                new Claim(ClaimTypes.Role, roleName),
                new Claim(JwtRegisteredClaimNames.Jti, tokenId),
                new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString())
            };

            // generación de la clave de seguridad y las credenciales de firma
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(GetJwtKey()));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            
            // creación del token jwt con tiempo de expiración desde appsettings
            var token = new JwtSecurityToken(
                issuer: GetJwtIssuer(),
                audience: GetJwtAudience(),
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(GetJwtExpirationMinutes()),
                notBefore: DateTime.UtcNow,
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
        #endregion

        /// <summary>
        /// genera un refresh token seguro.
        /// flujo: genera tokenId (uuid) -> genera randomValue (32 bytes) -> retorna formato tokenId.randomValue.
        /// </summary>
        /// <returns>refresh token en formato tokenId.randomValue.</returns>
        #region generar refresh token
        public string GenerateRefreshToken()
        {
            // generar tokenId público (uuid)
            var tokenId = Guid.NewGuid().ToString();
            
            // generar randomValue seguro (32 bytes = 64 caracteres hex)
            var randomBytes = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomBytes);
            var randomValue = Convert.ToHexString(randomBytes).ToLower();
            
            // retornar token en formato tokenId.randomValue
            return $"{tokenId}.{randomValue}";
        }

        /// <summary>
        /// Extrae el tokenId de un refresh token.
        /// Flujo: divide token por punto -> retorna primera parte (tokenId).
        /// </summary>
        /// <param name="refreshToken">Refresh token a procesar.</param>
        /// <returns>TokenId extraído o string vacío.</returns>
        public string ExtractTokenId(string refreshToken)
        {
            if (string.IsNullOrWhiteSpace(refreshToken))
                return string.Empty;
            
            var parts = refreshToken.Split('.');
            return parts.Length >= 2 ? parts[0] : string.Empty;
        }

        /// <summary>
        /// Extrae el randomValue de un refresh token.
        /// Flujo: divide token por punto -> retorna segunda parte (randomValue).
        /// </summary>
        /// <param name="refreshToken">Refresh token a procesar.</param>
        /// <returns>RandomValue extraído o string vacío.</returns>
        public string ExtractRandomValue(string refreshToken)
        {
            if (string.IsNullOrWhiteSpace(refreshToken))
                return string.Empty;
            
            var parts = refreshToken.Split('.');
            return parts.Length >= 2 ? parts[1] : string.Empty;
        }
        #endregion

        /// <summary>
        /// valida la configuración jwt del sistema.
        /// flujo: obtiene clave -> verifica no sea nula -> verifica longitud mínima (32 chars).
        /// </summary>
        #region validar configuración jwt
        private void ValidateJwtConfiguration()
        {
            var jwtKey = GetJwtKey();
            if (string.IsNullOrWhiteSpace(jwtKey))
                throw new InvalidOperationException(PA_BACKEND.DTOs.Common.SecureMessages.ConfigurationError);
            
            if (jwtKey.Length < 32) // mínimo 256 bits
                throw new InvalidOperationException(PA_BACKEND.DTOs.Common.SecureMessages.ConfigurationError);
        }
        #endregion

        /// <summary>
        /// extrae el claim jti (jwt id) de un token de acceso.
        /// flujo: parsea token -> busca claim jti -> retorna valor o string vacío.
        /// </summary>
        /// <param name="accessToken">token de acceso jwt.</param>
        /// <returns>jti extraído o string vacío.</returns>
        #region extraer claim jti
        public string ExtractJti(string accessToken)
        {
            if (string.IsNullOrWhiteSpace(accessToken))
                return string.Empty;

            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var jsonToken = tokenHandler.ReadJwtToken(accessToken);
                return jsonToken.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Jti)?.Value ?? string.Empty;
            }
            catch
            {
                return string.Empty;
            }
        }
        #endregion

        /// <summary>
        /// extrae la fecha de expiración de un token de acceso.
        /// flujo: parsea token -> busca claim exp -> convierte a DateTime o retorna MinValue
        /// </summary>
        /// <param name="accessToken">token de acceso JWT</param>
        /// <returns>fecha de expiración UTC o DateTime.MinValue si hay error</returns>
        #region extraer claim exp
        public DateTime ExtractExpiration(string accessToken)
        {
            if (string.IsNullOrWhiteSpace(accessToken))
                return DateTime.MinValue;

            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var jsonToken = tokenHandler.ReadJwtToken(accessToken);
                var expClaim = jsonToken.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Exp);
                
                if (expClaim == null)
                    return DateTime.MinValue;

                var exp = long.Parse(expClaim.Value);
                return DateTimeOffset.FromUnixTimeSeconds(exp).UtcDateTime;
            }
            catch
            {
                return DateTime.MinValue;
            }
        }
        #endregion
    }
}