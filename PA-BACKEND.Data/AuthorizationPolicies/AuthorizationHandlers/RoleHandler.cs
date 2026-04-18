using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using PA_BACKEND.AuthorizationPolicies.AuthorizationRequirements;

namespace PA_BACKEND.AuthorizationPolicies.AuthorizationHandlers
{
    public class RoleHandler : AuthorizationHandler<RoleRequirement>
    {
        protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, RoleRequirement requirement)
        {
            var userRole = context.User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)?.Value 
                            ?? context.User.Claims.FirstOrDefault(c => c.Type == "role")?.Value;

            if (string.IsNullOrEmpty(userRole))
                return;

            if (requirement.AllowedRoles.Any(r => r.Equals(userRole, StringComparison.OrdinalIgnoreCase)))
                context.Succeed(requirement);
        }
    }
}
