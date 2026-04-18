namespace PA_BACKEND.DTOs.Common
{
    // mensajes de error seguros que no exponen información interna
    public static class SecureMessages
    {
        public const string InternalServerError = "Error interno del servidor";
        public const string InvalidCredentials = "Credenciales inválidas";
        public const string InvalidToken = "Token inválido o expirado";
        public const string OperationNotAllowed = "Operación no permitida";
        public const string UserAlreadyExists = "El usuario ya está registrado";
        public const string InvalidEmail = "El formato del correo electrónico es inválido";
        public const string InvalidPassword = "La contraseña debe cumplir con los requisitos mínimos";
        public const string ValidationError = "Error de validación en los datos enviados";
        public const string PasswordRequirements = "La contraseña debe tener al menos 8 caracteres, incluyendo mayúsculas, minúsculas, números y caracteres especiales";
        public const string TokenExpired = "La sesión ha expirado";
        public const string SessionRevoked = "Sesión cerrada exitosamente";
        public const string SessionRevokedAll = "Sesión cerrada en todos los dispositivos exitosamente";
        public const string RegistrationSuccess = "Usuario registrado exitosamente";
        public const string LoginSuccess = "Inicio de sesión exitoso";
        public const string RefreshSuccess = "Token actualizado exitosamente";
        public const string ConfigurationError = "Error de configuración del sistema";
        public const string InvalidRequest = "Solicitud inválida";
    }

    // códigos de error estandarizados
    public static class ErrorCodes
    {
        public const string InternalError = "INTERNAL_ERROR";
        public const string AuthenticationFailed = "AUTH_FAILED";
        public const string TokenInvalid = "TOKEN_INVALID";
        public const string UserExists = "USER_EXISTS";
        public const string ValidationError = "VALIDATION_ERROR";
        public const string SessionExpired = "SESSION_EXPIRED";
    }

    // clase base para respuestas de API
    public class ResponseAPIDTO<T>
    {
        public bool Success { get; set; }
        public T? Data { get; set; }
        public string? Message { get; set; }
        public string? ErrorCode { get; set; }

        // método para crear una respuesta exitosa
        public static ResponseAPIDTO<T> SuccessResult(T data, string message = "Operación realizada correctamente.")
        {
            return new ResponseAPIDTO<T>
            {
                Success = true,
                Data = data,
                Message = message
            };
        }

        // método para crear una respuesta fallida
        public static ResponseAPIDTO<T> FailResult(string message, string? errorCode = null)
        {
            return new ResponseAPIDTO<T>
            {
                Success = false,
                Data = default(T),
                Message = message,
                ErrorCode = errorCode
            };
        }
    }


    // helper para respuestas simples
    public static class ResponseAPIHelper
    {
        // respuesta exitosa sin datos
        public static ResponseAPIDTO<object> Success(string message = "Operación realizada correctamente.")
        {
            return new ResponseAPIDTO<object>
            {
                Success = true,
                Data = new object(),
                Message = message
            };
        }

        // respuesta exitosa con datos
        public static ResponseAPIDTO<T> SuccessResult<T>(T data, string message = "Operación realizada correctamente.")
        {
            return new ResponseAPIDTO<T>
            {
                Success = true,
                Data = data,
                Message = message
            };
        }

        // respuesta fallida
        public static ResponseAPIDTO<object> Fail(string message, string? errorCode = null)
        {
            return new ResponseAPIDTO<object>
            {
                Success = false,
                Data = new object(),
                Message = message,
                ErrorCode = errorCode
            };
        }
    }
}