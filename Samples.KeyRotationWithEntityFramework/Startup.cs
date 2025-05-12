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
                            opt.UseSqlServer(keyRotationDbConnectionString);
                        });

                    krBuilder.ConfigureKeyRotation(conf =>
                    {
                        conf.Licensee = "DEMO";
                        conf.LicenseKey = "***LicenseKey Here***";
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
