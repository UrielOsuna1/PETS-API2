using Microsoft.Extensions.Configuration;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Dapper;

namespace PA_BACKEND.Middleware
{
    /// <summary>
    /// middleware para validación de tokens en lista negra.
    /// flujo: intercepta requests autorizados -> extrae jti del token -> verifica en base de datos -> bloquea si está revocado
    /// </summary>
    public class TokenBlacklistMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly string _connectionString;

        public TokenBlacklistMiddleware(RequestDelegate next, IConfiguration configuration)
        {
            _next = next;
            _connectionString = configuration.GetConnectionString("DefaultConnection") 
                ?? throw new InvalidOperationException(PA_BACKEND.DTOs.Common.SecureMessages.ConfigurationError);
        }

        /// <summary>
        /// procesa la solicitud y valida token en lista negra.
        /// flujo: verifica endpoint autorizado -> extrae token del header -> obtiene jti -> consulta lista negra -> bloquea si es necesario
        /// </summary>
        /// <param name="context">contexto http actual</param>
        #region validacion de token
        public async Task InvokeAsync(HttpContext context)
        {
            // solo verificar endpoints que requieren autorización
            var endpoint = context.GetEndpoint();
            if (endpoint == null)
            {
                await _next(context);
                return;
            }

            // verificar si el endpoint requiere autorización
            var authorizeData = endpoint.Metadata.GetMetadata<Microsoft.AspNetCore.Authorization.IAuthorizeData>();
            if (authorizeData == null)
            {
                await _next(context);
                return;
            }

            // extraer token del header
            var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();
            if (string.IsNullOrWhiteSpace(authHeader))
            {
                await _next(context);
                return;
            }

            // remover "Bearer " si existe
            var token = authHeader.Replace("Bearer ", "", StringComparison.OrdinalIgnoreCase);
            
            if (string.IsNullOrWhiteSpace(token))
            {
                await _next(context);
                return;
            }

            try
            {
                // extraer jti del token
                var tokenHandler = new JwtSecurityTokenHandler();
                var jsonToken = tokenHandler.ReadJwtToken(token);
                var jti = jsonToken.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Jti)?.Value;

                if (!string.IsNullOrWhiteSpace(jti))
                {
                    // verificar si está en la lista negra
                    if (await IsTokenBlacklisted(jti))
                    {
                        context.Response.StatusCode = 401;
                        context.Response.ContentType = "application/json";
                        
                        var response = new
                        {
                            Success = false,
                            Message = "Token has been revoked",
                            ErrorCode = "TOKEN_REVOKED"
                        };
                        
                        await context.Response.WriteAsJsonAsync(response);
                        return;
                    }
                }
            }
            catch (Exception)
            {
                // en caso de error, permitimos el paso (fail-safe)
            }

            await _next(context);
        }
        #endregion

        /// <summary>
        /// verifica si un token está en la lista negra.
        /// flujo: conecta a base de datos -> ejecuta función de verificación -> retorna resultado
        /// </summary>
        /// <param name="jti">identificador único del token</param>
        /// <returns>true si está en lista negra, false si no</returns>
        #region verificacion de token en lista negra
        private async Task<bool> IsTokenBlacklisted(string jti)
        {
            try
            {
                using var connection = new Npgsql.NpgsqlConnection(_connectionString);
                await connection.OpenAsync();

                // verificar si el token está en la lista negra
                var result = await connection.QueryFirstOrDefaultAsync<bool>(
                    "select * from public.fun_is_token_blacklisted(@p_jti)",
                    new { p_jti = Guid.Parse(jti) }
                );

                return result;
            }
            catch (Exception)
            {
                return false; // fail-safe: si hay error, asumimos que no está en lista negra
            }
        }
        #endregion
    }

    /// <summary>
    /// extensión para registrar middleware de validación de lista negra.
    /// </summary>
    #region extension para registrar middleware
    public static class TokenBlacklistMiddlewareExtensions
    {
        public static IApplicationBuilder UseTokenBlacklistValidation(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<TokenBlacklistMiddleware>();
        }
    }
    #endregion
}
