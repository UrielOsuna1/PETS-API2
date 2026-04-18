using System.Buffers;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Configuration;
// interfaces
using PA_BACKEND.Data.Interface;

namespace PA_BACKEND.Data.Repositories
{
    /// <summary>
    /// repositorio para operaciones criptográficas de encriptación/desencriptación.
    /// flujo: gestiona clave de encriptación -> desencripta datos base64 -> valida timestamps anti-replay
    /// </summary>
    public class CryptoRepository : ICryptoRepository
    {
        private readonly byte[] _key;

        public CryptoRepository(IConfiguration configuration)
        {
            var keyHex = configuration["Encryption:Key"]
                ?? throw new InvalidOperationException(PA_BACKEND.DTOs.Common.SecureMessages.ConfigurationError);

            if (keyHex.Length != 32)
                throw new InvalidOperationException(PA_BACKEND.DTOs.Common.SecureMessages.ConfigurationError);

            _key = Convert.FromHexString(keyHex);
        }

        /// <summary>
        /// encripta una cadena a base64 usando AES-GCM.
        /// flujo: convierte string a bytes -> genera iv -> encripta -> retorna base64
        /// </summary>
        /// <param name="plainText">cadena a encriptar</param>
        /// <returns>cadena encriptada en base64 o string vacío si es nulo/vacío</returns>
        #region encriptar datos
        public string Encrypt(string plainText)
        {
            if (string.IsNullOrEmpty(plainText))
                return plainText;

            try
            {
                var plaintextBytes = Encoding.UTF8.GetBytes(plainText);
                var iv = new byte[12];
                RandomNumberGenerator.Fill(iv);
                
                var ciphertextBuffer = ArrayPool<byte>.Shared.Rent(plaintextBytes.Length);
                var tagBuffer = ArrayPool<byte>.Shared.Rent(16);
                
                try
                {
                    using var aes = new AesGcm(_key, 16);
                    aes.Encrypt(iv, plaintextBytes.AsSpan(), ciphertextBuffer.AsSpan(0, plaintextBytes.Length), tagBuffer.AsSpan(0, 16));
                    
                    var result = new byte[12 + plaintextBytes.Length + 16];
                    Buffer.BlockCopy(iv, 0, result, 0, 12);
                    Buffer.BlockCopy(ciphertextBuffer, 0, result, 12, plaintextBytes.Length);
                    Buffer.BlockCopy(tagBuffer, 0, result, 12 + plaintextBytes.Length, 16);
                    
                    return Convert.ToBase64String(result);
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(ciphertextBuffer, true);
                    ArrayPool<byte>.Shared.Return(tagBuffer, true);
                }
            }
            catch (Exception ex)
            {
                throw new CryptographicException("Encryption failed", ex);
            }
        }
        #endregion

        /// <summary>
        /// desencripta una cadena en base64 usando AES-GCM.
        /// flujo: convierte base64 a bytes -> extrae iv, tag y ciphertext -> desencripta -> retorna string
        /// </summary>
        /// <param name="encryptedBase64">cadena encriptada en base64</param>
        /// <returns>cadena desencriptada o string vacío si es nulo/vacío</returns>
        #region desencriptar datos
        public string Decrypt(string encryptedBase64)
        {
            if (string.IsNullOrEmpty(encryptedBase64))
                return encryptedBase64;

            try
            {
                var encryptedBytes = Convert.FromBase64String(encryptedBase64);

                if (encryptedBytes.Length < 28)
                    throw new CryptographicException($"Invalid encrypted data: too short ({encryptedBytes.Length} bytes)");

                var iv = encryptedBytes.AsSpan(0, 12);
                var tag = encryptedBytes.AsSpan(encryptedBytes.Length - 16, 16);
                var ciphertext = encryptedBytes.AsSpan(12, encryptedBytes.Length - 28);

                var plaintextBuffer = ArrayPool<byte>.Shared.Rent(ciphertext.Length);
                try
                {
                    using var aes = new AesGcm(_key, 16);
                    aes.Decrypt(iv, ciphertext, tag, plaintextBuffer.AsSpan(0, ciphertext.Length));
                    var result = Encoding.UTF8.GetString(plaintextBuffer, 0, ciphertext.Length);
                    return result;
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(plaintextBuffer, true);
                }
            }
            catch (FormatException ex)
            {
                throw new CryptographicException("Invalid base64 format", ex);
            }
            catch (CryptographicException ex)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw;
            }
        }
        #endregion

        /// <summary>
        /// desencripta campos específicos de un objeto.
        /// flujo: recorre campos especificados -> obtiene valores -> desencripta -> actualiza objeto
        /// </summary>
        /// <param name="obj">objeto a procesar</param>
        /// <param name="fields">nombres de campos a desencriptar</param>
        /// <returns>objeto con campos desencriptados</returns>
        #region desencriptar campos de objeto
        public T DecryptFields<T>(T obj, string[] fields) where T : class
        {
            if (obj == null || fields == null || fields.Length == 0)
                return obj;

            var type = typeof(T);

            foreach (var fieldName in fields)
            {
                var property = type.GetProperty(fieldName,
                    BindingFlags.IgnoreCase | BindingFlags.Public | BindingFlags.Instance);

                if (property == null || property.PropertyType != typeof(string))
                    continue;

                var currentValue = property.GetValue(obj) as string;
                if (!string.IsNullOrEmpty(currentValue))
                {
                    var decryptedValue = Decrypt(currentValue);
                    property.SetValue(obj, decryptedValue);
                }
            }

            return obj;
        }
        #endregion

        /// <summary>
        /// valida timestamp para prevenir ataques de replay.
        /// flujo: valida formato -> compara con hora UTC -> verifica ventana de tiempo permitida
        /// </summary>
        /// <param name="timestamp">timestamp a validar</param>
        /// <param name="maxMinutes">ventana máxima de minutos permitida</param>
        #region validacion anti-replay
        public void ValidateTimestamp(string timestamp, int maxMinutes = 5)
        {
            if (string.IsNullOrEmpty(timestamp))
                throw new InvalidOperationException(PA_BACKEND.DTOs.Common.SecureMessages.InvalidRequest);

            if (!DateTime.TryParse(timestamp, out var requestTime))
                throw new InvalidOperationException(PA_BACKEND.DTOs.Common.SecureMessages.InvalidRequest);

            var now = DateTime.UtcNow;
            var diff = now - requestTime.ToUniversalTime();

            if (diff.TotalMinutes > maxMinutes)
                throw new InvalidOperationException(PA_BACKEND.DTOs.Common.SecureMessages.InvalidRequest);

            if (diff.TotalMinutes < -1)
                throw new InvalidOperationException(PA_BACKEND.DTOs.Common.SecureMessages.InvalidRequest);
        }
        #endregion
    }
}
