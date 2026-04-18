using PA_BACKEND.DTOs.Auth;

namespace PA_BACKEND.Data.Interface
{
    public interface IAuthRepository
    {
        // método para registrar un nuevo usuario
        Task<ResponseLoginDTO> RegisterUserAsync(RegisterUserDTO registerUserDTO);

        // método para autenticar a un usuario existente
        Task<ResponseLoginDTO> LoginUserAsync(RequestLoginDTO requestLoginDTO);

        // método para refrescar tokens con rotación segura
        Task<ResponseLoginDTO> RefreshTokenAsync(string refreshToken);

        // método para cerrar sesión en todos los dispositivos
        Task RevokeAllUserSessionsAsync(int userId);

        // método para cerrar sesión
        Task LogoutAsync(int userId, string accessToken);

        // método para obtener información de sesión del usuario
        Task<SessionInformationDTO> GetSessionInformationAsync(int userId);
    }
}