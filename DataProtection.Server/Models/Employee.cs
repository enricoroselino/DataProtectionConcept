﻿using UUIDNext;

namespace DataProtection.Server.Models;

public class Employee
{
    // EF Core
    private Employee()
    {
    }

    public Guid Id { get; private set; }
    public string Name { get; private set; } = default!;
    public string Ssn { get; private set; } = default!;

    public static Employee CreateNew(string name, string ssn)
    {
        return new Employee()
        {
            Id = Uuid.NewSequential(),
            Name = name,
            Ssn = ssn,
        };
    }
}