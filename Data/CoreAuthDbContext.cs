using core_auth.Model;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace core_auth.Data;

public class CoreAuthDbContext : IdentityDbContext<ApplicationUser>
{
    public CoreAuthDbContext(DbContextOptions<CoreAuthDbContext> options)
        : base(options)
    {
    }
    
    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.Entity<ApplicationUser>()
            .ToTable("Users");
        
        builder.Entity<ApplicationUser>()
            .Property(u => u.CreatedDate)
            .HasDefaultValueSql("GETUTCDATE()"); 
    }
    
}