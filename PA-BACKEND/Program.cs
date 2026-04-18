using PA_BACKEND.Middleware;

var builder = WebApplication.CreateBuilder(args);

// cargar variables de entorno
builder.Configuration.AddEnvironmentVariables();

builder.Services.AddControllers()
    .AddJsonOptions(options =>
    {
        options.JsonSerializerOptions.PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase;
    });

// cors
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
            policy.WithOrigins("https://tudominio.com")
                  .AllowAnyMethod()
                  .AllowAnyHeader()
                  .AllowCredentials();
        }
    });
});

// manejo de errores de modelo
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

// 🔥 FIX: evitar crash si no hay variables en build
var jwtKey = builder.Configuration["Jwt:Key"] ?? "TEMP_KEY_123456789";
var jwtIssuer = builder.Configuration["Jwt:Issuer"] ?? "TEMP_ISSUER";
var jwtAudience = builder.Configuration["Jwt:Audience"] ?? "TEMP_AUDIENCE";

// auth
builder.Services.AddAuthentication("Bearer")
    .AddJwtBearer("Bearer", options =>
    {
        options.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
        {
            ValidateAudience = true,
            ValidateIssuer = true,
            ValidateIssuerSigningKey = true,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero,
            IssuerSigningKey = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(
                System.Text.Encoding.UTF8.GetBytes(jwtKey)),
            ValidIssuer = jwtIssuer,
            ValidAudience = jwtAudience,
            RoleClaimType = System.Security.Claims.ClaimTypes.Role
        };
    });

builder.Services.AddAuthorization();

// DI
builder.Services.AddScoped<PA_BACKEND.Data.Interface.IAuthRepository, PA_BACKEND.Data.Repositories.AuthRepository>();
builder.Services.AddScoped<PA_BACKEND.Data.Interface.ITokenRepository, PA_BACKEND.Data.Repositories.TokenRepository>();
builder.Services.AddScoped<PA_BACKEND.Data.Interface.ICryptoRepository, PA_BACKEND.Data.Repositories.CryptoRepository>();
builder.Services.AddScoped<PA_BACKEND.Data.Interface.IGatewayRepository, PA_BACKEND.Data.Repositories.GatewayRepository>();
builder.Services.AddScoped<PA_BACKEND.Data.Interface.IAuditLogRepository, PA_BACKEND.Data.Repositories.AuditLogRepository>();

builder.Services.AddHttpContextAccessor();

// db
builder.Services.AddSingleton<PA_BACKEND.Data.PostgreSQLConfiguration>();
builder.Services.AddSingleton<Microsoft.Extensions.Configuration.IConfiguration>(builder.Configuration);

// swagger
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// errores globales
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

app.UseCors("AllowAll");

app.UseAuthorizationHeaderFix();
app.UseTokenBlacklistValidation();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

// 🔥 Railway
var port = Environment.GetEnvironmentVariable("PORT") ?? "8080";
app.Run($"http://0.0.0.0:{port}");