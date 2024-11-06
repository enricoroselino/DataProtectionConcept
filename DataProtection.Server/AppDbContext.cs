using DataProtection.Server.Ciphers;
using DataProtection.Server.Ciphers.Interfaces;
using DataProtection.Server.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace DataProtection.Server;

public class AppDbContext : DbContext
{
    private readonly ITextCipher _cipher;

    public AppDbContext(DbContextOptions<AppDbContext> options, ITextCipher cipher) : base(options)
    {
        _cipher = cipher;
    }

    public DbSet<Employee> Employees { get; init; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        var textCipherConverter =
            new ValueConverter<string, string>(
                v => _cipher.Encrypt(v).GetAwaiter().GetResult(),
                v => _cipher.Decrypt(v).GetAwaiter().GetResult()
            );

        modelBuilder.Entity<Employee>()
            .Property(e => e.Ssn)
            .HasConversion(textCipherConverter)
            .IsRequired();
    }
}