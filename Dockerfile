FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /app

# 🔥 copiar solo csproj primero (mejor práctica)
COPY PA-BACKEND/*.csproj ./PA-BACKEND/
COPY PA-BACKEND.Data/*.csproj ./PA-BACKEND.Data/
COPY PA-BACKEND.DTOs/*.csproj ./PA-BACKEND.DTOs/
COPY PA-BACKEND.Model/*.csproj ./PA-BACKEND.Model/

RUN dotnet restore PA-BACKEND/PA-BACKEND.csproj

# 🔥 ahora sí copiar todo
COPY . .

RUN dotnet publish PA-BACKEND/PA-BACKEND.csproj -c Release -o out

FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app

COPY --from=build /app/out .

ENTRYPOINT ["dotnet", "PA-BACKEND.dll"]