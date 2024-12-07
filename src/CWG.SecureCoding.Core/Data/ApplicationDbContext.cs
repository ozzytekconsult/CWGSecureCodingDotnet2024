using CWG.SecureCoding.Core.Models;
using CWG.SecureCoding.Core.Models.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace CWG.SecureCoding.Core.Data;

/// <summary>
/// Application database context
/// </summary>
public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

   
    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

       
    }
}
