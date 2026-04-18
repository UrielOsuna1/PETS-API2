using PA_BACKEND.Middleware;

var builder = WebApplication.CreateBuilder(args);

// add services to the container

// forzar carga de variables de entorno del launchSettings.json
var launchSettings = builder.Configuration.AddJsonFile("Properties/launchSettings.json", optional: true, reloadOnChange: true);
builder.Configuration.AddEnvironmentVariables();

builder.Services.AddControllers()
    .AddJsonOptions(options =>
    {
        options.JsonSerializerOptions.PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase;
    });

// cors configuration - restringir en producción
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", policy =>
    {
        var isDevelopment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") == "Development";
        if (isDevelopment)
        {
            policy.AllowAnyOrigin()
                  .AllowAnyMethod()
                  .AllowAnyHeader();
        }
        else
        {
            // configuración más restrictiva para producción
            policy.WithOrigins("https://tudominio.com") // reemplazar con dominios permitidos
                  .AllowAnyMethod()
                  .AllowAnyHeader()
                  .AllowCredentials();
        }
    });
});

// middleware personalizado para manejar errores de validación de modelo
builder.Services.Configure<Microsoft.AspNetCore.Mvc.ApiBehaviorOptions>(options =>
{
    options.InvalidModelStateResponseFactory = context =>
    {
        var errors = context.ModelState.Values
            .SelectMany(v => v.Errors)
            .Select(e => e.ErrorMessage)
            .ToList();

        var response = new PA_BACKEND.DTOs.Common.ResponseAPIDTO<object>
        {
            Success = false,
            Data = new object(),
            Message = errors.Count > 0 ? string.Join("; ", errors) : PA_BACKEND.DTOs.Common.SecureMessages.ValidationError,
            ErrorCode = PA_BACKEND.DTOs.Common.ErrorCodes.ValidationError
        };

        return new Microsoft.AspNetCore.Mvc.BadRequestObjectResult(response);
    };
});

// add authentication and authorization con validaciones estrictas
builder.Services.AddAuthentication("Bearer")
    .AddJwtBearer("Bearer", options =>
    {
        options.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
        {
            ValidateAudience = true,
            ValidateIssuer = true,
            ValidateIssuerSigningKey = true,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero, // sin skew para mayor seguridad
            IssuerSigningKey = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(
                System.Text.Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"] ?? throw new InvalidOperationException(PA_BACKEND.DTOs.Common.SecureMessages.ConfigurationError))),
            ValidIssuer = builder.Configuration["Jwt:Issuer"] ?? throw new InvalidOperationException(PA_BACKEND.DTOs.Common.SecureMessages.ConfigurationError),
            ValidAudience = builder.Configuration["Jwt:Audience"] ?? throw new InvalidOperationException(PA_BACKEND.DTOs.Common.SecureMessages.ConfigurationError),
            // mapear el claim de rol para que [Authorize(Roles = "X")] funcione
            RoleClaimType = System.Security.Claims.ClaimTypes.Role
        };
    });

builder.Services.AddAuthorization();

// dependency injection - repositories
builder.Services.AddScoped<PA_BACKEND.Data.Interface.IAuthRepository, PA_BACKEND.Data.Repositories.AuthRepository>();
builder.Services.AddScoped<PA_BACKEND.Data.Interface.ITokenRepository, PA_BACKEND.Data.Repositories.TokenRepository>();
builder.Services.AddScoped<PA_BACKEND.Data.Interface.ICryptoRepository, PA_BACKEND.Data.Repositories.CryptoRepository>();
builder.Services.AddScoped<PA_BACKEND.Data.Interface.IGatewayRepository, PA_BACKEND.Data.Repositories.GatewayRepository>();
builder.Services.AddScoped<PA_BACKEND.Data.Interface.IAuditLogRepository, PA_BACKEND.Data.Repositories.AuditLogRepository>();

// http context accessor para obtener ip del cliente
builder.Services.AddHttpContextAccessor();

// database configuration
builder.Services.AddSingleton<PA_BACKEND.Data.PostgreSQLConfiguration>();
builder.Services.AddSingleton<Microsoft.Extensions.Configuration.IConfiguration>(builder.Configuration);

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new() { 
        Title = "PA Backend API", 
        Version = "v1",
        Description = "API para el sistema de protección animal"
    });
    
    // configuración para jwt bearer
    c.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme. Example: \"Authorization: Bearer {token}\"",
        Name = "Authorization",
        In = Microsoft.OpenApi.Models.ParameterLocation.Header,
        Type = Microsoft.OpenApi.Models.SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });
    
    c.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement
    {
        {
            new Microsoft.OpenApi.Models.OpenApiSecurityScheme
            {
                Reference = new Microsoft.OpenApi.Models.OpenApiReference
                {
                    Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

var app = builder.Build();

// configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "PA Backend API v1");
        c.RoutePrefix = "swagger";
    });
}

// middleware global para manejo de excepciones
app.UseExceptionHandler(errorApp =>
{
    errorApp.Run(async context =>
    {
        context.Response.StatusCode = 500;
        context.Response.ContentType = "application/json";
        
        var response = new PA_BACKEND.DTOs.Common.ResponseAPIDTO<object>
        {
            Success = false,
            Data = new object(),
            Message = PA_BACKEND.DTOs.Common.SecureMessages.InternalServerError,
            ErrorCode = PA_BACKEND.DTOs.Common.ErrorCodes.InternalError
        };

        await context.Response.WriteAsJsonAsync(response);
    });
});

// use CORS
app.UseCors("AllowAll");

// fix authorization headers (agrega Bearer si falta)
app.UseAuthorizationHeaderFix();

// validate token blacklist (revoked tokens)
app.UseTokenBlacklistValidation();

// app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
