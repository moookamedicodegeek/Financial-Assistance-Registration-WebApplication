using FireSharp.Config;
using FireSharp.Interfaces;
using Google.Cloud.Firestore;
using Google.Apis.Auth.OAuth2;
using Google.Cloud.Firestore.V1;
using Grpc.Auth;
using Microsoft.AspNetCore.Authentication.Cookies;
using FirebaseAdmin;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

// Step 1: Initialize Firebase Admin SDK
var firebaseCredential = GoogleCredential.FromFile(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ServiceCredentials", "flowfinance.json"));
FirebaseApp.Create(new AppOptions
{
    Credential = firebaseCredential,
    ProjectId = "flowfinance-cf09d"
});

// Step 2: Add Authentication Services and Cookie Authentication with modified settings

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
})
.AddCookie(options =>
{
    options.LoginPath = "/Home/Login";
    options.AccessDeniedPath = "/Home/AccessDenied";
    options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
    options.SlidingExpiration = true;
    options.Cookie.Name = "Flow.Finance.Auth";
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;

    // Add authorization handling
    options.Events = new CookieAuthenticationEvents
    {
        OnRedirectToLogin = context =>
        {
            if (context.Request.Path.StartsWithSegments("/api"))
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            }
            context.Response.Redirect(context.RedirectUri);
            return Task.CompletedTask;
        },
        OnRedirectToAccessDenied = context =>
        {
            context.Response.Redirect("/Home/AccessDenied");
            return Task.CompletedTask;
        }
    };
});

// Add authorization policies
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy =>
        policy.RequireRole("Admin"));
    options.AddPolicy("UserOnly", policy =>
        policy.RequireRole("User"));
});

// Step 3: Configure Session with more specific settings
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(20);
    options.Cookie.Name = "Flow.Finance.Session";
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
});

// Step 4: Register Firebase Realtime Database client
builder.Services.AddSingleton<IFirebaseClient>(provider =>
{
    var firebaseConfig = new FirebaseConfig
    {
        AuthSecret = "cKjwsFI0AzVRfU3U80K06rjO2vvdOnXTfmpeXUbf",
        BasePath = "https://flowfinance-cf09d-default-rtdb.firebaseio.com"
    };
    return new FireSharp.FirebaseClient(firebaseConfig);
});

// Step 5: Register Firestore client
builder.Services.AddSingleton<FirestoreDb>(provider =>
{
    string jsonPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ServiceCredentials", "flowfinance.json");
    GoogleCredential credential;
    using (var stream = new FileStream(jsonPath, FileMode.Open, FileAccess.Read))
    {
        credential = GoogleCredential.FromStream(stream);
    }
    var firestoreClient = new FirestoreClientBuilder
    {
        ChannelCredentials = credential.ToChannelCredentials()
    }.Build();
    return FirestoreDb.Create("flowfinance-cf09d", firestoreClient);
});

// Step 6: Add HTTP Context Accessor
builder.Services.AddHttpContextAccessor();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}
else
{
    // Add development-specific middleware for debugging
    app.UseDeveloperExceptionPage();
}

// Add custom middleware to log requests (helps diagnose redirect loops)
app.Use(async (context, next) =>
{
    var logger = context.RequestServices.GetRequiredService<ILogger<Program>>();
    logger.LogInformation(
        "Request: {Method} {Path} User: {User}",
        context.Request.Method,
        context.Request.Path,
        context.User?.Identity?.IsAuthenticated);

    await next();
});

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

// Important: Order matters here
app.UseSession();
app.UseAuthentication();
app.UseAuthorization();

// Add middleware to prevent redirect loops
app.Use(async (context, next) =>
{
    var path = context.Request.Path.Value?.ToLower();

    // Skip redirect checking for static files and certain paths
    if (path.StartsWith("/css") ||
        path.StartsWith("/js") ||
        path.StartsWith("/images") ||
        path == "/home/login" ||
        path == "/home/registration")
    {
        await next();
        return;
    }

    var redirectCount = context.Session.GetInt32("RedirectCount") ?? 0;

    if (redirectCount > 3) // Lower the threshold
    {
        context.Session.Remove("RedirectCount");
        await context.Response.WriteAsync("Redirect loop detected. Please try logging in again.");
        return;
    }

    context.Session.SetInt32("RedirectCount", redirectCount + 1);

    await next();

    // Reset count on successful responses
    if (context.Response.StatusCode == 200 || context.Response.StatusCode == 302)
    {
        context.Session.Remove("RedirectCount");
    }
});

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
