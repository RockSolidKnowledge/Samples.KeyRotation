using System.Text.Json;
using IdentityExpress.Identity;
using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;
using Rsk.KeyRotation.EntityFramework;
using Samples.KeyRotationWithEntityFramework.Data;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Samples.KeyRotationWithEntityFramework;

public class Worker(IServiceProvider serviceProvider) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        Console.WriteLine("################## Worker Start");
        
        await using var scope = serviceProvider.CreateAsyncScope();
        await EnsureAllDatabasesAreCreated(scope);
        await CreateMvcClientIfNotExists(scope);
        await CreateFakeUserBobIfNotExists(scope);
        await CreateEmailScopeIfNotExists(scope);
        await SaveAllChanges(scope);
        
        Console.WriteLine("################## Worker End");
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    private async Task EnsureAllDatabasesAreCreated(IServiceScope scope)
    {
        //Create the database backed by the ApplicationDbContext.
        var applicationDbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        var aResult = await applicationDbContext.Database.EnsureCreatedAsync();
        Console.WriteLine(aResult ? "Created ApplicationDbContext" : "Didn't Create ApplicationDbContext");

        //Create the database backed by the KeyRotationDbContext.
        var keyRotationDbContext = scope.ServiceProvider.GetRequiredService<KeyRotationDbContext>();
        var krResult = await keyRotationDbContext.Database.EnsureCreatedAsync();
        Console.WriteLine(krResult ? "Created KeyRotationDbContext" : "Didn't Create KeyRotationDbContext");
    }

    private Task CreateMvcClientIfNotExists(IServiceScope scope)
    {
        return CreateClientIfNotExists(scope, "mvc", ocd =>
        {
            ocd.ClientId = "mvc";
            ocd.ClientSecret = "901564A5-E7FE-42CB-B10D-61EF6A8F3654";
            ocd.ConsentType = ConsentTypes.Explicit;
            ocd.DisplayName = "MVC client application";
            ocd.RedirectUris.Add(new Uri("https://localhost:44338/callback/login/local"));
            ocd.PostLogoutRedirectUris.Add(new Uri("https://localhost:44338/callback/logout/local"));

            ocd.Permissions.UnionWith(new[]
            {
                Permissions.Endpoints.Authorization,
                Permissions.Endpoints.EndSession,
                Permissions.Endpoints.Token,
                Permissions.GrantTypes.AuthorizationCode,
                Permissions.ResponseTypes.Code,
                Permissions.Scopes.Email,
                Permissions.Scopes.Profile,
                Permissions.Scopes.Roles});
            ocd.Requirements.Add(Requirements.Features.ProofKeyForCodeExchange);
        });
    }

    private async Task CreateClientIfNotExists(IServiceScope scope, string clientId, Action<OpenIddictApplicationDescriptor> descriptorCoonfiguration)
    {
        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        if (await manager.FindByClientIdAsync(clientId) == null)
        {
            var newClientDescriptor = CreateAndConfigureOpenIddictApplicationDescriptor(descriptorCoonfiguration);
            await manager.CreateAsync(newClientDescriptor);
        }
    }

    private OpenIddictApplicationDescriptor CreateAndConfigureOpenIddictApplicationDescriptor(Action<OpenIddictApplicationDescriptor> configuration)
    {
        var od = new OpenIddictApplicationDescriptor();
        configuration(od);
        return od;
    }

    private Task CreateFakeUserBobIfNotExists(IServiceScope scope)
    {
        return CreateUserIfNotExists(scope, "bob@test.fake", user =>
        {
            user.UserName = "bob@test.fake";
            user.Email = "bob@test.fake";
        }, "Password123!");
    }

    private async Task CreateUserIfNotExists(IServiceScope scope, string userName, Action<IdentityExpressUser> userConfiguration, string userPassword)
    {
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityExpressUser>>();
        if (await userManager.FindByNameAsync(userName) == null)
        {
            var user = new IdentityExpressUser();
            userConfiguration(user);
            await userManager.CreateAsync(user, userPassword);
        }
    }

    private Task CreateEmailScopeIfNotExists(IServiceScope scope)
    {
        var claims = new[] { "email" };
        var serializedClaims = JsonSerializer.Serialize(claims);
        using var jsonDocument = JsonDocument.Parse(serializedClaims);
        var claimsElemennt = jsonDocument.RootElement.Clone();
        return CreateScopeIfNotExists(scope, "email", x =>
        {
            x.Name = "email";
            x.Resources.Add("https://localhost:5001/saml");
            x.Properties.Add("Claims", claimsElemennt);
        });
    }

    private static async Task CreateScopeIfNotExists(IServiceScope scope, string scopeName, Action<OpenIddictScopeDescriptor> scopeConfiguration)
    {
        var scopeManager = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
        if (await scopeManager.FindByNameAsync(scopeName) == null)
        {
            var scopeDescriptor = new OpenIddictScopeDescriptor();
            scopeConfiguration(scopeDescriptor);

            await scopeManager.CreateAsync(scopeDescriptor);
        }
    }
    
    private async Task SaveAllChanges(IServiceScope scope)
    {
        var applicationDbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        await applicationDbContext.SaveChangesAsync();
        var keyRotationDbContext = scope.ServiceProvider.GetRequiredService<KeyRotationDbContext>();
        await keyRotationDbContext.SaveChangesAsync();
    }
}