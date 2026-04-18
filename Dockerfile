# Imagen base de .NET
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /app

# Copiar todo
COPY . .

# Restaurar y publicar
RUN dotnet restore PA-BACKEND/PA-BACKEND.csproj
RUN dotnet publish PA-BACKEND/PA-BACKEND.csproj -c Release -o out

# Runtime
FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build /app/out .

ENTRYPOINT ["dotnet", "PA-BACKEND.dll"]