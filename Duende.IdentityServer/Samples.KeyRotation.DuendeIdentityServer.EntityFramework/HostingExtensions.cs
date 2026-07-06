// Copyright (c) Duende Software. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using System.Reflection;
using Samples.KeyRotation.DuendeIdentityServer.EntityFramework;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Rsk.KeyRotation.EntityFrameworkCore.DependencyInjection;
using Rsk.KeyRotation.OpenIdentityServer.DependencyInjection;

internal static class HostingExtensions
{
    public static WebApplication ConfigureServices(this WebApplicationBuilder builder)
    {
        builder.Services.AddRazorPages();

        builder.Services.AddDataProtection()
            .SetApplicationName("Samples.KeyRotation");

        var idsvrBuilder = builder.Services
            .AddIdentityServer(options =>
            {
                // Duende Key Rotation Disabled
                options.KeyManagement.Enabled = false;
                
                // see https://docs.duendesoftware.com/identityserver/fundamentals/resources/api-scopes
                options.EmitStaticAudienceClaim = true;
                options.PushedAuthorization.AllowUnregisteredPushedRedirectUris = true;

                options.StrictClientAssertionAudienceValidation = true;
            })
            .AddTestUsers(TestUsers.Users);

        idsvrBuilder.AddInMemoryIdentityResources(Resources.Identity);
        idsvrBuilder.AddInMemoryApiScopes(Resources.ApiScopes);
        idsvrBuilder.AddInMemoryApiResources(Resources.ApiResources);
        idsvrBuilder.AddInMemoryClients(Clients.List);

        // this is only needed for the JAR and JWT samples and adds supports for JWT-based client authentication
        idsvrBuilder.AddJwtBearerClientAuthentication();

        idsvrBuilder.AddRskKeyRotation(krBuilder =>
        {
            krBuilder.UseEntityFrameworkCore()
                .AddKeyRotationDbContext(dbOptions =>
                {
                    dbOptions.UseSqlite("Data Source=db/KeyRotationSample_KeyRotationDb.db;", 
                        bld => bld.MigrationsAssembly(Assembly.GetExecutingAssembly().GetName().Name));
                });

            krBuilder
                .AddLicense("DEMO", builder.Configuration.GetValue<string>("LicenseKey") ?? string.Empty)
                .UseRsaForSigning(3072);
        });        

        builder.Services.AddAuthentication();

        return builder.Build();
    }

    public static WebApplication ConfigurePipeline(this WebApplication app)
    {
        if (app.Environment.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }

        app.UseStaticFiles();

        app.UseRouting();
        app.UseIdentityServer();
        app.UseAuthorization();
        app.MapRazorPages();

        return app;
    }
}
