using IdentityExpress.Identity;
using Microsoft.EntityFrameworkCore;

namespace Samples.KeyRotation.OpenIddict.EntityFramework.Data;

public class ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
    : IdentityExpressDbContext<IdentityExpressUser>(options);
