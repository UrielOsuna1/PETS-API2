namespace PA_BACKEND.Data.Interface
{
    public interface ITokenRepository
    {
        // para generar token con tokenId automático
        string GenerateAccessToken(int userId, string roleName);
        
        // para generar token con tokenId específico (vinculado a refresh token)
        string GenerateAccessToken(int userId, string roleName, string tokenId);

        // método para generar refresh token
        string GenerateRefreshToken();

        // método para extraer tokenId del refresh token
        string ExtractTokenId(string refreshToken);

        // método para extraer randomValue del refresh token
        string ExtractRandomValue(string refreshToken);

        // método para extraer JTI del access token
        string ExtractJti(string accessToken);

        // método para extraer expiración del access token
        DateTime ExtractExpiration(string accessToken);
    }
}