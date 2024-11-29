using DataProtection.Server;
using DataProtection.Server.Ciphers;
using DataProtection.Server.Ciphers.Algorithms.Aes;
using DataProtection.Server.FileHandlers;
using DataProtection.Server.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services
    .AddAntiforgery()
    .Configure<KestrelServerOptions>(options => { options.Limits.MaxRequestBodySize = 1024 * 1024 * 1024; });

builder.Services
    .AddOptions<AesCipherSettings>()
    .BindConfiguration(AesCipherSettings.Section)
    .ValidateDataAnnotations()
    .ValidateOnStart();

builder.Services
    .AddTransient<ITextCipher, TextCipher>()
    .AddTransient<IFileCipher, FileCipher>()
    .AddScoped<IFileHandler, LocalFileHandler>();

builder.Services.AddDbContext<AppDbContext>(options => { options.UseSqlite("Data Source=DataProtection.db"); });

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseAntiforgery();
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

app.MapPost("/upload",
        async (IFormFile file, IFileHandler fileHandler, CancellationToken cancellationToken) =>
        {
            var savePath = Path.Combine("FileStore", file.FileName);

            await using var fileStream = file.OpenReadStream();
            await fileHandler.Save(fileStream, savePath, cancellationToken);

            // LEAVE OPEN TO RETURNED VIA Result.File
            var loadStream = await fileHandler.Load(savePath, cancellationToken);
            return Results.File(loadStream, file.ContentType, enableRangeProcessing: false);
        })
    .DisableAntiforgery();


await app.RunAsync();

namespace DataProtection.Server
{
    public record NewEmployeeDto(string Name, string Ssn);
}