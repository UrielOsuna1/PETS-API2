namespace PA_BACKEND.Data.Interface
{
    public interface ICryptoRepository
    {
        // método para encriptar una cadena a base64
        string Encrypt(string plainText);
        
        // método para desencriptar una cadena en base64
        string Decrypt(string encryptedBase64);
        
        // método para desencriptar campos específicos de un objeto
        T DecryptFields<T>(T obj, string[] fields) where T : class;
        
        // método para validar el timestamp de la petición
        void ValidateTimestamp(string timestamp, int maxMinutes = 5);
    }
}
