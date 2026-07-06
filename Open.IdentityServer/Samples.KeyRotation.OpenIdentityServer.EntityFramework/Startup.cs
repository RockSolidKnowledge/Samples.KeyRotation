// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using Open.IdentityServer;
using IdentityServerHost.Quickstart.UI;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using System.Reflection;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Configuration;
using Rsk.KeyRotation.EntityFrameworkCore.DependencyInjection;
using Rsk.KeyRotation.OpenIdentityServer.DependencyInjection;

namespace Samples.KeyRotation.OpenIdentityServer.EntityFramework;

public class Startup(IConfiguration configuration)
{
    private IConfiguration Configuration { get; } = configuration;

    public void ConfigureServices(IServiceCollection services)
    {
        services.AddControllersWithViews();

        services.AddDataProtection()
            .SetApplicationName("Samples.KeyRotation");
        
        var builder = services.AddIdentityServer()
            .AddTestUsers(TestUsers.Users)
            .AddInMemoryIdentityResources(Config.IdentityResources)
            .AddInMemoryApiScopes(Config.ApiScopes)
            .AddInMemoryClients(Config.Clients)
            .AddRskKeyRotation(krBuilder =>
            {
                krBuilder.UseEntityFrameworkCore()
                    .AddKeyRotationDbContext(dbOptions =>
                    {
                        dbOptions.UseSqlite("Data Source=db/KeyRotationSample_KeyRotationDb.db;", 
                            bld => bld.MigrationsAssembly(Assembly.GetExecutingAssembly().GetName().Name));
                    });

                // Here is where key rotation is configured in this Open.IdentityServer sample for testing
                krBuilder
                    .AddLicense("DEMO", Configuration.GetValue<string>("LicenseKey") ?? string.Empty)
                    .UseRsaForSigning()
                    .ConfigureKeyRotation(conf =>
                    {
                        Random rnd = new Random();
                        conf.CheckInterval = rnd.Next(1, 10) * 60;
                        Console.Write("############## CheckInterval: {0}", conf.CheckInterval);

                        conf.SigningKeyPublishTime = TimeSpan.FromMinutes(5);
                        conf.SigningKeyLifetime = TimeSpan.FromMinutes(20);
                        conf.SigningKeyRetirementTime = TimeSpan.FromMinutes(5);

                        conf.EnableSigningKeyRotation = true;
                    });
            });

        services.AddAuthentication()
            .AddOpenIdConnect("oidc", "Demo Samples.KeyRotation.OpenIdentityServer.EntityFramework", options =>
            {
                options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                options.SignOutScheme = IdentityServerConstants.SignoutScheme;
                options.SaveTokens = true;

                options.Authority = "https://demo.identityserver.io/";
                options.ClientId = "interactive.confidential";
                options.ClientSecret = "secret";
                options.ResponseType = "code";

                options.TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = "name",
                    RoleClaimType = "role"
                };
            });
    }

    public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
    {
        if (env.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }

        app.UseStaticFiles();
        app.UseRouting();

        app.UseIdentityServer();
        app.UseAuthorization();

        app.UseEndpoints(endpoints => { endpoints.MapDefaultControllerRoute(); });
    }
}