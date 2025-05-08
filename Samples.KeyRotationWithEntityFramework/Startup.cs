using Duende.IdentityModel;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Quartz;
using Rsk.KeyRotation.OpenIddict.DependencyInjection;
using Samples.KeyRotationWithEntityFramework.Data;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Samples.KeyRotationWithEntityFramework;

public class Startup(IConfiguration configuration)
{
    private IConfiguration Configuration { get; } = configuration;

    public void ConfigureServices(IServiceCollection services)
    {
        services.AddControllersWithViews();
        services.AddRazorPages();
        var openIddictDbConnectionString = Configuration.GetConnectionString("OpenIddictDb");
        services.AddDbContext<ApplicationDbContext>(options =>
        {
            //Configure the database provider to use.
            options.UseSqlServer(openIddictDbConnectionString);

            // Register the entity sets needed by OpenIddict.
            // Note: use the generic overload if you need
            // to replace the default OpenIddict entities.
            options.UseOpenIddict();
        });

        services.AddDatabaseDeveloperPageExceptionFilter();

        // Register the Identity services.
        services.AddIdentity<ApplicationUser, IdentityRole>()
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddDefaultTokenProviders()
            .AddDefaultUI();

        services.Configure<IdentityOptions>(options =>
        {
            options.ClaimsIdentity.UserIdClaimType = JwtClaimTypes.Subject;
            options.ClaimsIdentity.UserNameClaimType = JwtClaimTypes.Name;
            options.ClaimsIdentity.RoleClaimType = JwtClaimTypes.Role;
            options.ClaimsIdentity.EmailClaimType = JwtClaimTypes.Email;
        });
        
        // OpenIddict offers native integration with Quartz.NET to perform scheduled tasks
        // (like pruning orphaned authorizations/tokens from the database) at regular intervals.
        services.AddQuartz(options =>
        {
            options.UseSimpleTypeLoader();
            options.UseInMemoryStore();
        });

        // Register the Quartz.NET service and configure it to block shutdown until jobs are complete.
        services.AddQuartzHostedService(options => options.WaitForJobsToComplete = true);

        services.AddOpenIddict()

            // Register the OpenIddict core components.
            .AddCore(options =>
            {
                // Configure OpenIddict to use the Entity Framework Core stores and models.
                // Note: call ReplaceDefaultEntities() to replace the default OpenIddict entities.
                options.UseEntityFrameworkCore()
                       .UseDbContext<ApplicationDbContext>();

                // Enable Quartz.NET integration.
                options.UseQuartz();
            })

            // Register the OpenIddict server components.
            .AddServer(options =>
            {
                // Enable the authorization, logout, token and userinfo endpoints.
                options.SetAuthorizationEndpointUris("connect/authorize")
                       .SetEndSessionEndpointUris("connect/logout")
                       .SetTokenEndpointUris("connect/token")
                       .SetUserInfoEndpointUris("connect/userinfo");

                // Mark the "email", "profile" and "roles" scopes as supported scopes.
                options.RegisterScopes(Scopes.Email, Scopes.Profile, Scopes.Roles);

                // Note: this sample only uses the authorization code flow, but you can enable
                // the other flows if you need to support implicit, password or client credentials.
                options.AllowAuthorizationCodeFlow();

                // Register the signing and encryption credentials.
                options.AddDevelopmentEncryptionCertificate()
                       .AddDevelopmentSigningCertificate();

                // Register the ASP.NET Core host and configure the ASP.NET Core-specific options.
                options.UseAspNetCore()
                    .EnableAuthorizationEndpointPassthrough()
                    .EnableEndSessionEndpointPassthrough()
                    .EnableTokenEndpointPassthrough()
                    .EnableUserInfoEndpointPassthrough()
                    .EnableStatusCodePagesIntegration();

                // Adding Key Rotation component to OpenIddict instance
                options.AddKeyRotation(krBuilder =>
                {
                    krBuilder.UseEntityFrameworkCore()
                        .AddKeyRotationDbContext(opt =>
                        {
                            var keyRotationDbConnectionString = Configuration.GetConnectionString("KeyRotationDb");
                            opt.UseSqlServer(keyRotationDbConnectionString, c => c.MigrationsAssembly("Samples.KeyRotationWithEntityFramework"));
                        });

                    krBuilder.ConfigureKeyRotation(conf =>
                    {
                        conf.Licensee = "DEMO";
                        conf.LicenseKey = "eyJhdXRoIjoiREVNTyIsImV4cCI6IjIwMjUtMDYtMDhUMDA6MDA6MDAiLCJpYXQiOiIyMDI1LTA1LTA4VDE0OjIzOjM2Iiwib3JnIjoiREVNTyIsImF1ZCI6NX0=.Y5XdVMzlXDr8HOYWnojqbzep/k2dyL9LH29Pe6WG6u0vnAs6w8S/jsvrBqoaSc//yJJVpTMSQwOOxI+7PeQmIQaUPmuJs4YQjdKtQZ7IcGvvRkV4m9dXElglBKtz3q9UztVNqxvoT/ly+qU6XM+qSUoYr4wpsfX+qH1vd0VQsAtref762FYofvTucLYO8egAndn486j0Xve2QLlgWY+9TxuZB0xRVemvQT+aPpRMz5vg/FAkhr0teNWUDTiX8VUXOf9BI9/lT2P/csO2gHqq2Qi33ujlyJ0fx5wyfywSdHm4ITYI0fXRFvHLbKh8CFQvUY2tzKKqvEieTu9sR5OFrexes9/WIWbjJZmaZcZU0WiUXgd0x2MM9jZz97y/m078fV8MW8dsJteav2+6xE+H1a3sSrEOZfHCU6DZUlYU0Yv+z078tF8Y9YPuEJhatrl/mHe8dtFgHgNH1btc3+uDexMmVi2i3uMoYqB/3Gczms2PkaPrA6Qd3uQY5N23CjsxIwdzAwwNFnERuchjPnJ4iY4IcMjWf9oBW3Lp7YCfkcH19fC/9U9rfN9OHcziPQPIOAT4j5jLxZWaM+6qsG3MjkGpVH9x2XLK1tfVZiFu3isBhdnCO3+VWLjNSLj3Kbju34j59AqWBeO2Fpt/65t2mW/5aiGB3pYQy846fi3uNn4=";

                        conf.CheckInterval = Configuration.GetValue<int>("KRCheckInterval");
                        Console.WriteLine($"####### CheckInterval: {conf.CheckInterval}");
                        
                        conf.KeyPublishTime = TimeSpan.FromSeconds(10);
                        conf.KeyLifetime = TimeSpan.FromSeconds(40);
                        conf.KeyRetirementTime = TimeSpan.FromSeconds(10);
                    });
                });
            })

            // Register the OpenIddict validation components.
            .AddValidation(options =>
            {
                // Import the configuration from the local OpenIddict server instance.
                options.UseLocalServer();

                // Register the ASP.NET Core host.
                options.UseAspNetCore();
            });

        // Register the worker responsible for seeding the database.
        // Note: in a real world application, this step should be part of a setup script.
        services.AddHostedService<Worker>();
    }

    public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
    {
        if (env.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
            app.UseMigrationsEndPoint();
        }
        else
        {
            app.UseStatusCodePagesWithReExecute("~/error");
            // app.UseExceptionHandler("~/error");

            // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
            //app.UseHsts();
        }
        app.UseHttpsRedirection();
        app.UseStaticFiles();

        app.UseRouting();

        app.UseAuthentication();
        app.UseAuthorization();

        app.UseEndpoints(endpoints =>
        {
            endpoints.MapControllers();
            endpoints.MapDefaultControllerRoute();
            endpoints.MapRazorPages();
        });
    }
}
