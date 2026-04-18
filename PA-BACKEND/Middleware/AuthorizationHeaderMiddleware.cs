using System.Text.RegularExpressions;

namespace PA_BACKEND.Middleware
{
    /// <summary>
    /// middleware para corregir headers de autorización.
    /// flujo: verifica si falta 'Bearer ' en el header -> valida formato jwt -> agrega prefijo si es válido
    /// </summary>
    public class AuthorizationHeaderMiddleware
    {
        private readonly RequestDelegate _next;

        public AuthorizationHeaderMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        /// <summary>
        /// procesa la solicitud y corrige el header de autorización si es necesario.
        /// flujo: extrae header -> verifica si falta 'Bearer ' -> valida formato jwt -> agrega prefijo
        /// </summary>
        /// <param name="context">contexto http actual</param>
        #region procesar solicitud
        public async Task InvokeAsync(HttpContext context)
        {
            var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();
            
            // si no hay header, continuar normalmente
            if (string.IsNullOrWhiteSpace(authHeader))
            {
                await _next(context);
                return;
            }

            // si el header no tiene "Bearer ", agregarlo automáticamente
            if (!authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                // verificar si parece un jwt (formato base64url con 3 partes)
                if (IsValidJwtFormat(authHeader))
                {
                    context.Request.Headers["Authorization"] = $"Bearer {authHeader}";
                }
            }

            await _next(context);
        }
        #endregion

        /// <summary>
        /// valida si un token tiene formato jwt válido.
        /// flujo: divide token en 3 partes -> verifica longitud mínima de cada parte
        /// </summary>
        /// <param name="token">token a validar</param>
        /// <returns>true si tiene formato jwt válido, false si no</returns>
        #region validar formato jwt
        private bool IsValidJwtFormat(string token)
        {
            // jwt tiene 3 partes separadas por puntos
            var parts = token.Split('.');
            if (parts.Length != 3)
                return false;

            // verificar que las partes tengan longitud razonable
            return parts[0].Length > 10 && parts[1].Length > 10 && parts[2].Length > 10;
        }
        #endregion
    }

    /// <summary>
    /// extensión para registrar middleware de corrección de headers de autorización.
    /// </summary>
    #region extensiones para registrar middleware
    public static class AuthorizationHeaderMiddlewareExtensions
    {
        public static IApplicationBuilder UseAuthorizationHeaderFix(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<AuthorizationHeaderMiddleware>();
        }
    }
    #endregion
}
