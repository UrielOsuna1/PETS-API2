using Microsoft.AspNetCore.Authorization;

namespace PA_BACKEND.AuthorizationPolicies.AuthorizeAttributes
{
    public static class Roles
    {
        public const string Admin = "ADMIN";
        public const string Adoptante = "ADOPTANTE";
    }

    public class RoleAuthorizeAttribute : AuthorizeAttribute
    {
        public const string RolePrefix = "ROLE%";

        public RoleAuthorizeAttribute(params string[] roleKeys) 
        {
            if (roleKeys == null || roleKeys.Length == 0)
            {
                throw new ArgumentException("Debe proporcionar al menos un rol.", nameof(roleKeys));
            }

            Policy = $"{RolePrefix}{string.Join('%', roleKeys)}";
        }

        public static string[] GetRoleKeysFromPolicy(string policyName) 
        {
            if (string.IsNullOrEmpty(policyName) || !policyName.StartsWith(RolePrefix))
            {
                return Array.Empty<string>();
            }

            return policyName.Substring(RolePrefix.Length).Split('%', StringSplitOptions.RemoveEmptyEntries);
        }
    }
}
