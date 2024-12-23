﻿using DataProtection.Server.Ciphers;
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

        // can't use dependency injection in Fluent API
        var cryptoConverter = new ValueConverter<string, string>(
            v => _cipher.Encrypt(v),
            v => _cipher.Decrypt(v)
        );

        modelBuilder.Entity<Employee>()
            .Property(e => e.Ssn)
            .HasConversion(cryptoConverter)
            .IsRequired();
    }
}