using Flow_Finance.Models;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using Firebase.Auth;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;
using FireSharp.Interfaces;
using FireSharp.Response;
using FireSharp.Config;

namespace Flow_Finance.Controllers
{
    public class HomeController : BaseController
    {
        private readonly ILogger<HomeController> _logger;
        private readonly FirebaseAuthProvider _auth;
        private readonly IFirebaseConfig _firebaseConfig;  // FireSharp config for Realtime Database
        private readonly IFirebaseClient _firebaseClient;  // FireSharp client

        // Constructor to initialize Firebase authentication and database
        public HomeController(ILogger<HomeController> logger) : base(logger)
        {
            _logger = logger;

            // Firebase authentication configuration
            _auth = new FirebaseAuthProvider(new Firebase.Auth.FirebaseConfig("AIzaSyDMUZwnk0UUjYYkTO4n88vAGq2KayiP5kE")); // Replace with actual API key

            // FireSharp configuration for Firebase Realtime Database
            _firebaseConfig = new FireSharp.Config.FirebaseConfig
            {
                AuthSecret = "cKjwsFI0AzVRfU3U80K06rjO2vvdOnXTfmpeXUbf",
                BasePath = "https://flowfinance-cf09d-default-rtdb.firebaseio.com"
            };

            // Initialize FireSharp Firebase client
            _firebaseClient = new FireSharp.FirebaseClient(_firebaseConfig);
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        public IActionResult Registration()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Registration(RegisterModel userModel)
        {
            try
            {
                // Create the user with Firebase Authentication
                var fbAuthLink = await _auth.CreateUserWithEmailAndPasswordAsync(userModel.Email, userModel.Password);
                string localId = fbAuthLink.User.LocalId; // Access LocalId after user is created
                string token = fbAuthLink.FirebaseToken;

                if (!string.IsNullOrEmpty(token))
                {
                    // Save token in session
                    HttpContext.Session.SetString("_UserToken", token);

                    // Create UserModel instance and assign properties
                    var newUser = new UserModel
                    {
                        Uid = localId, // Assign the Firebase Uid
                        Email = userModel.Email // Assign the email from RegisterModel
                        // Initialize other properties as needed
                    };

                    // Save user to Realtime Database
                    var setResponse = await _firebaseClient.SetAsync($"User/{newUser.Uid}", newUser);
                    if (setResponse.StatusCode == System.Net.HttpStatusCode.OK)
                    {
                        // Redirect to profile creation after successful registration
                        return RedirectToAction("Login", "Home");
                    }
                    else
                    {
                        ModelState.AddModelError(string.Empty, "Error saving user data.");
                    }
                }
            }
            catch (FirebaseAuthException ex)
            {
                // Handle specific "email already in use" exception
                if (ex.ResponseData.Contains("EMAIL_EXISTS"))
                {
                    ModelState.AddModelError(string.Empty, "This email is already registered. Please use a different email or log in.");
                }
                else
                {
                    ModelState.AddModelError(string.Empty, ex.Message);
                }
            }

            return View(userModel);
        }

        public IActionResult Login()
        {
            // If user is already authenticated, redirect appropriately
            if (User.Identity.IsAuthenticated)
            {
                if (User.IsInRole("Admin"))
                {
                    return RedirectToAction("Index", "Admin");
                }
                return RedirectToAction("Details", "User", new { id = User.FindFirst("user_id")?.Value });
            }
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(LoginModel loginModel)
        {
            try
            {
                if (string.IsNullOrEmpty(loginModel.Email) || string.IsNullOrEmpty(loginModel.Password))
                {
                    ModelState.AddModelError(string.Empty, "Email and password are required.");
                    return View(loginModel);
                }

                // Admin Login Check - Case insensitive email comparison
                if (loginModel.Email.Equals("admin@gmail.com", StringComparison.OrdinalIgnoreCase) &&
                    loginModel.Password == "Admin12#")
                {
                    var adminClaims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Name, "Administrator"),
                        new Claim(ClaimTypes.Email, loginModel.Email),
                        new Claim(ClaimTypes.Role, "Admin"),
                        new Claim("user_id", "admin") // Adding a user_id claim for consistency
                    };

                    var adminIdentity = new ClaimsIdentity(adminClaims, CookieAuthenticationDefaults.AuthenticationScheme);
                    var authProperties = new AuthenticationProperties
                    {
                        IsPersistent = true,
                        ExpiresUtc = DateTime.UtcNow.AddHours(2), // Longer session for admin
                        AllowRefresh = true
                    };

                    await HttpContext.SignInAsync(
                        CookieAuthenticationDefaults.AuthenticationScheme,
                        new ClaimsPrincipal(adminIdentity),
                        authProperties);

                    _logger.LogInformation("Admin login successful");
                    return RedirectToAction("Index", "Admin");
                }

                // Regular User Login
                try
                {
                    var fbAuthLink = await _auth.SignInWithEmailAndPasswordAsync(loginModel.Email, loginModel.Password);
                    string token = fbAuthLink.FirebaseToken;
                    string uid = fbAuthLink.User.LocalId;

                    if (!string.IsNullOrEmpty(token))
                    {
                        var claims = new List<Claim>
                        {
                            new Claim(ClaimTypes.Email, loginModel.Email),
                            new Claim("user_id", uid),
                            new Claim(ClaimTypes.Role, "User") // Adding explicit user role
                        };

                        var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                        var authProperties = new AuthenticationProperties
                        {
                            IsPersistent = true,
                            ExpiresUtc = DateTime.UtcNow.AddMinutes(30),
                            AllowRefresh = true
                        };

                        await HttpContext.SignInAsync(
                            CookieAuthenticationDefaults.AuthenticationScheme,
                            new ClaimsPrincipal(claimsIdentity),
                            authProperties);

                        // Clear any existing redirect count
                        HttpContext.Session.Remove("RedirectCount");

                        try
                        {
                            // Check user profile status
                            FirebaseResponse response = await _firebaseClient.GetAsync($"User/{uid}");

                            if (response.Body == "null")
                            {
                                return RedirectToAction("Create", "User");
                            }

                            var user = JsonConvert.DeserializeObject<UserModel>(response.Body);

                            if (IsIncompleteProfile(user))
                            {
                                return RedirectToAction("Create", "User");
                            }

                            return RedirectToAction("Details", "User", new { id = uid });
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(ex, "Error checking user profile after login");
                            return RedirectToAction("Create", "User");
                        }
                    }

                    ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                    return View(loginModel);
                }
                catch (FirebaseAuthException ex)
                {
                    _logger.LogError(ex, "Firebase authentication error");
                    ModelState.AddModelError(string.Empty, "Invalid email or password.");
                    return View(loginModel);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Login error");
                ModelState.AddModelError(string.Empty, "An error occurred during login.");
                return View(loginModel);
            }
        }


        private bool IsIncompleteProfile(UserModel user)
        {
            return string.IsNullOrEmpty(user.Name) ||
                   string.IsNullOrEmpty(user.Surname) ||
                   string.IsNullOrEmpty(user.Address) ||
                   user.DOB == null;
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        public async Task<IActionResult> SignOut()
        {
            // Clear the authentication cookies
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            HttpContext.Session.Remove("_UserToken");  // Clear session if any

            return RedirectToAction("Login");
        }

        public IActionResult AboutUs()
        {
            return View();
        }

        public IActionResult Download()
        {
            return View();
        }
        public IActionResult DownloadFile()
        {
            var filePath = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot/Downloads", "app-release.apk");
            var mimeType = "application/vnd.android.package-archive"; // MIME type for APK files
            var fileName = "FlowFinanceApp.apk"; // Desired file name when downloaded

            if (System.IO.File.Exists(filePath))
            {
                return PhysicalFile(filePath, mimeType, fileName);
            }
            else
            {
                return NotFound("The file does not exist.");
            }
        }

     }
}
