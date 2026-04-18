using Microsoft.Extensions.Configuration;
using Npgsql;
using Microsoft.Extensions.Logging;

namespace PA_BACKEND.Data
{
    #region PostgreSQLConnection
    public class PostgreSQLConnection
    {
        public PostgreSQLConnection(string connectionString) => ConnectionString = connectionString;
        public string ConnectionString { get; set; }   
    }
    #endregion

    #region PostgreSQLConfiguration
    public class PostgreSQLConfiguration
    {
        private readonly string _connectionString;
        private readonly ILogger<PostgreSQLConfiguration> _logger;

        public PostgreSQLConfiguration(IConfiguration configuration, ILogger<PostgreSQLConfiguration> logger)
        {
            _logger = logger;
            
            // Leer desde appsettings.json primero
            var connectionString = configuration["ConnectionStrings:DefaultConnection"];
            
            if (!string.IsNullOrEmpty(connectionString))
            {
                _connectionString = connectionString;
            }
            else
            {
                // Fallback a variables de entorno si no está en appsettings
                connectionString = configuration["CONNECTION_STRING"];
                if (!string.IsNullOrEmpty(connectionString))
                {
                    _connectionString = connectionString;
                }
                else
                {
                    throw new InvalidOperationException("No se pudo obtener la cadena de conexión ni de appsettings.json ni de variables de entorno");
                }
            }
        }

        public NpgsqlConnection GetConnection()
        {
            return new NpgsqlConnection(_connectionString);
        }
    }
    #endregion
}
