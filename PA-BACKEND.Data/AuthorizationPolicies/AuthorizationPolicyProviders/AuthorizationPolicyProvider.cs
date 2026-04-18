using Microsoft.AspNetCore.Authorization;
using PA_BACKEND.AuthorizationPolicies;
using PA_BACKEND.AuthorizationPolicies.AuthorizationRequirements;
using PA_BACKEND.AuthorizationPolicies.AuthorizeAttributes;

namespace PA_BACKEND.AuthorizationPolicies.AuthorizationPolicyProviders
{
    public class RoleAuthorizationPolicyProvider : IAuthorizationPolicyProvider
    {
        public Task<AuthorizationPolicy?> GetPolicyAsync(string policyName)
        {
            if (policyName.StartsWith(RoleAuthorizeAttribute.RolePrefix))
            {
                var roleKeys = RoleAuthorizeAttribute.GetRoleKeysFromPolicy(policyName);

                var policy = new AuthorizationPolicyBuilder()
                    .AddRequirements(new RoleRequirement(roleKeys))
                    .Build();

                return Task.FromResult<AuthorizationPolicy?>(policy);
            }

            return Task.FromResult<AuthorizationPolicy?>(null);
        }

        public Task<AuthorizationPolicy> GetDefaultPolicyAsync()
        {
            return Task.FromResult(new AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser()
                .Build());
        }

        public Task<AuthorizationPolicy?> GetFallbackPolicyAsync()
        {
            return Task.FromResult<AuthorizationPolicy?>(null);
        }
    }
}
