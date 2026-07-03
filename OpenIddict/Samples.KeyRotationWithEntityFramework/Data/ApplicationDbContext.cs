using IdentityExpress.Identity;
using Microsoft.EntityFrameworkCore;

namespace Samples.KeyRotationWithEntityFramework.Data;

public class ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
    : IdentityExpressDbContext<IdentityExpressUser>(options);
