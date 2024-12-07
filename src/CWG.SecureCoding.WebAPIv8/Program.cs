using CWG.SecureCoding.Core.Security;
using CWG.SecureCoding.WebAPIv8.Middleware;

namespace CWG.SecureCoding.WebAPIv8
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.
            builder.Services.AddControllers();
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen();

            // Add security features
            builder.Services.AddAntiforgery(options =>
            {
                options.HeaderName = "X-XSRF-TOKEN";
                options.Cookie.Name = "XSRF-TOKEN";
                options.Cookie.HttpOnly = true;
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                options.Cookie.SameSite = SameSiteMode.Strict;
            });

            // Add rate limiting
            //builder.Services.AddRateLimiter(RateLimitingSetup.ConfigureRateLimiting());

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseHttpsRedirection();
            app.UseSecurityHeaders(); // Custom security headers
            app.UseRateLimiter(); // Rate limiting
            app.UseAuthorization();
            app.MapControllers();

            app.Run();
        }
    }
}
