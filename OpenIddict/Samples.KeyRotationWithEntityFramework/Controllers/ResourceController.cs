using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Validation.AspNetCore;
using Samples.KeyRotationWithEntityFramework.Data;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Samples.KeyRotationWithEntityFramework.Controllers;

[Route("api")]
public class ResourceController(UserManager<ApplicationUser> userManager) : Controller
{
    [Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
    [HttpGet("message")]
    public async Task<IActionResult> GetMessage()
    {
        var subject = User.GetClaim(Claims.Subject) ?? 
                      throw new InvalidOperationException("Unable to get subject from ClaimsPrinciple");
        var user = await userManager.FindByIdAsync(subject);

        if (user is not null) return Content($"{user.UserName} has been successfully authenticated.");
            
        return Challenge(
            authenticationSchemes: OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme,
            properties: new AuthenticationProperties(new Dictionary<string, string?>
            {
                [OpenIddictValidationAspNetCoreConstants.Properties.Error] = Errors.InvalidToken,
                [OpenIddictValidationAspNetCoreConstants.Properties.ErrorDescription] =
                    "The specified access token is bound to an account that no longer exists."
            }));
    }
}
