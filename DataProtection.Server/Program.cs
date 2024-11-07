using DataProtection.Server;
using DataProtection.Server.Ciphers;
using DataProtection.Server.Ciphers.Interfaces;
using DataProtection.Server.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddOptions<CipherSettings>()
    .BindConfiguration(CipherSettings.Section);

builder.Services
    .AddScoped<ITextCipher, TextCipher>()
    .AddScoped<IFileCipher, FileCipher>();

builder.Services.AddDbContext<AppDbContext>(options => { options.UseSqlite("Data Source=DataProtection.db"); });

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.MapPost("/employee", async ([FromBody] NewEmployeeDto dto, AppDbContext dbContext) =>
{
    var newEmployee = Employee.CreateNew(dto.Name, dto.Ssn);
    var existingEmployee = dbContext.Employees.FirstOrDefault(e => e.Ssn == dto.Ssn);
    if (existingEmployee is not null) return Results.Conflict("Employee already exists");

    await dbContext.Employees.AddAsync(newEmployee);
    await dbContext.SaveChangesAsync();
    return Results.Ok(new { newEmployee.Id, newEmployee.Name, newEmployee.Ssn });
});

app.MapGet("/employee", async (AppDbContext dbContext) =>
{
    var employees = await dbContext.Employees.ToListAsync();
    return Results.Ok(employees);
});

app.Run();

namespace DataProtection.Server
{
    public record NewEmployeeDto(string Name, string Ssn);
}