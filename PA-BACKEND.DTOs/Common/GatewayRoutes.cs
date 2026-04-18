namespace PA_BACKEND.DTOs.Common
{
    public static class GatewayRoutes
    {
        public class RouteDefinition
        {
            // identificador único del endpoint (ej: "auth_login")
            public string Key { get; set; } = string.Empty;

            // nombre descriptivo para logs
            public string Name { get; set; } = string.Empty;

            // indica si el endpoint requiere autorización JWT
            public bool RequiresAuth { get; set; }

            // indica si los campos sensibles (email, password) deben desencriptarse
            public bool RequiresDecryption { get; set; }
        }

        // diccionario de rutas soportadas por el gateway.
        // key: identificador del endpoint que envía el frontend
        public static readonly Dictionary<string, RouteDefinition> Routes = new()
        {
            ["auth_login"] = new RouteDefinition
            {
                Key = "auth_login",
                Name = "Autenticación de usuario",
                RequiresAuth = false, // false si es publico
                RequiresDecryption = true
            },
            ["auth_register"] = new RouteDefinition
            {
                Key = "auth_register",
                Name = "Registro de usuario",
                RequiresAuth = false,
                RequiresDecryption = false  // registro puede manejar su propia validación
            },
            ["auth_refresh"] = new RouteDefinition
            {
                Key = "auth_refresh",
                Name = "Refrescar token",
                RequiresAuth = false,
                RequiresDecryption = false
            },
            ["auth_logout"] = new RouteDefinition
            {
                Key = "auth_logout",
                Name = "Cerrar sesión",
                RequiresAuth = true, // true si requiere token de sesión
                RequiresDecryption = false
            },
            ["auth_logout_all"] = new RouteDefinition
            {
                Key = "auth_logout_all",
                Name = "Cerrar sesión en todos los dispositivos",
                RequiresAuth = true,
                RequiresDecryption = false
            },
            ["auth_session_info"] = new RouteDefinition
            {
                Key = "auth_session_info",
                Name = "Obtener información de sesión",
                RequiresAuth = true,
                RequiresDecryption = false
            },
            ["audit_logs_get"] = new RouteDefinition
            {
                Key = "audit_logs_get",
                Name = "Consultar logs de auditoría",
                RequiresAuth = true,
                RequiresDecryption = false
            }
        };

        // obtiene la definición de ruta por key
        public static RouteDefinition? GetRoute(string key)
        {
            return Routes.TryGetValue(key.ToLower(), out var route) ? route : null;
        }

        // valida si un endpoint está registrado
        public static bool IsValidRoute(string key)
        {
            return Routes.ContainsKey(key.ToLower());
        }
    }
}
