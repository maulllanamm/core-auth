using core_auth.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace core_auth.Data;

public class CoreAuthDbContext : IdentityDbContext<ApplicationUser,  IdentityRole<Guid>, Guid>
{
    public CoreAuthDbContext(DbContextOptions<CoreAuthDbContext> options)
        : base(options)
    {
    }
    
    public DbSet<RefreshToken> RefreshTokens { get; set; } = null!;
    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.Entity<ApplicationUser>()
            .ToTable("Users");
        
        builder.Entity<ApplicationUser>()
            .Property(u => u.CreatedDate)
            .HasDefaultValueSql("GETUTCDATE()"); 
        
        builder.Entity<RefreshToken>()
            .HasOne(rt => rt.User) 
            .WithMany()
            .HasForeignKey(rt => rt.UserId) 
            .IsRequired() 
            .OnDelete(DeleteBehavior.Cascade); 

        builder.Entity<RefreshToken>()
            .Property(rt => rt.Created)
            .HasDefaultValueSql("GETUTCDATE()"); 
    }
    
}