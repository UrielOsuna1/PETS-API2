using Microsoft.AspNetCore.Authorization;

namespace PA_BACKEND.AuthorizationPolicies.AuthorizationRequirements
{
    public class RoleRequirement : IAuthorizationRequirement
    {
        public string[] AllowedRoles { get; }

        public RoleRequirement(params string[] allowedRoles)
        {
            if (allowedRoles == null || allowedRoles.Length == 0)
            {
                throw new ArgumentException("Debe proporcionar al menos un rol permitido.", nameof(allowedRoles));
            }

            AllowedRoles = allowedRoles;
        }
    }
}
