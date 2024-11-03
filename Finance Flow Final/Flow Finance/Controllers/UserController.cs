using Firebase.Auth;
using FireSharp.Interfaces;
using FireSharp.Response;
using Flow_Finance.Models;
using Google.Cloud.Firestore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Newtonsoft.Json;
using System;
using System.Security.Claims;
using System.Threading.Tasks;
using FirebaseAdmin.Auth;
using Microsoft.AspNetCore.Authentication.Cookies;
using Amazon.JSII.Runtime;
using Google.Api;

namespace Flow_Finance.Controllers
{
    [Authorize]
    [UserProfile]
    public class UserController : BaseController
    {
        private readonly IFirebaseClient _firebaseClient;
        private readonly FirestoreDb _firestoreDb;
        private readonly string _firebaseApiKey = "AIzaSyDMUZwnk0UUjYYkTO4n88vAGq2KayiP5kE";
        private readonly FirebaseAuthProvider _authProvider;

        private readonly IFirebaseConfig config = new FireSharp.Config.FirebaseConfig
        {
            AuthSecret = "cKjwsFI0AzVRfU3U80K06rjO2vvdOnXTfmpeXUbf",
            BasePath = "https://flowfinance-cf09d-default-rtdb.firebaseio.com"
        };
        private IFirebaseClient client;
        private static readonly HttpClient client1 = new HttpClient();

        public UserController(ILogger<UserController> logger, IFirebaseClient firebaseClient, FirestoreDb firestoreDb, IConfiguration configuration) : base(logger)
        {
            _firebaseClient = firebaseClient;
            _firestoreDb = firestoreDb;
            client = new FireSharp.FirebaseClient(config);
            _firebaseApiKey = configuration.GetValue<string>("Firebase:ApiKey");
            _authProvider = new FirebaseAuthProvider(new FirebaseConfig(_firebaseApiKey));

        }

        [HttpGet]
        public async Task<IActionResult> Create()
        {
            // Get user auth details
            var email = User.FindFirst(ClaimTypes.Email)?.Value;
            var userUid = User.FindFirst("user_id")?.Value;

            if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(userUid))
            {
                return RedirectToAction("Login", "Home");
            }

            // Check if profile exists
            var existingUser = await GetUserProfile(userUid);
            if (existingUser != null && !IsIncompleteProfile(existingUser))
            {
                return RedirectToAction("Details", new { id = userUid });
            }

            // Pre-populate the model with email and UID
            var model = new UserModel
            {
                Email = email,
                Uid = userUid
            };

            return View(model);
        }

        private string GenerateRandomCardNumber()
        {
            var random = new Random();
            return string.Join("", Enumerable.Range(0, 10).Select(_ => random.Next(0, 10).ToString()));
        }

        [HttpPost]
        public async Task<IActionResult> Create(UserModel userModel, IFormFile file)
        {
            try
            {
                // Ensure UID and email are set
                var userUid = User.FindFirst("user_id")?.Value;
                var email = User.FindFirst(ClaimTypes.Email)?.Value;

                if (string.IsNullOrEmpty(userUid) || string.IsNullOrEmpty(email))
                {
                    return RedirectToAction("Login", "Home");
                }

                userModel.Uid = userUid;
                userModel.Email = email;

                // Generate a random card number
                userModel.CardNumber = GenerateRandomCardNumber();

                // Handle file upload if present
                if (file != null && file.Length > 0)
                {
                    var fileName = $"{userUid}_{DateTime.Now.Ticks}_{file.FileName}";
                    var filePath = Path.Combine("wwwroot/images", fileName);
                    using (var stream = new FileStream(filePath, FileMode.Create))
                    {
                        await file.CopyToAsync(stream);
                    }
                    userModel.ImageUrl = $"/images/{fileName}";
                }

                // Save to Realtime Database - MODIFIED THIS SECTION
                if (client == null)
                {
                    client = new FireSharp.FirebaseClient(config);
                }

                // First, try to set the data
                SetResponse setResponse = client.Set($"User/{userUid}", userModel);

                if (setResponse.StatusCode != System.Net.HttpStatusCode.OK)
                {
                    ModelState.AddModelError(string.Empty, "Failed to create profile in Realtime Database");
                    return View(userModel);
                }

                // Then save to Firestore
                try
                {
                    await SaveUserToFirestore(userModel, userUid);
                }
                catch (Exception firestoreEx)
                {
                    _logger.LogError($"Firestore save failed: {firestoreEx.Message}");
                    // Continue even if Firestore fails, as we have the data in Realtime DB
                }

                // If we get here, the profile was created successfully
                TempData["SuccessMessage"] = "Profile created successfully!";

                // Ensure we're passing the correct ID for the redirect
                return RedirectToAction(nameof(Details), new { id = userUid });
            }
            catch (Exception ex)
            {
                _logger.LogError($"Profile creation error: {ex.Message}");
                ModelState.AddModelError(string.Empty, $"Error creating profile: {ex.Message}");
                return View(userModel);
            }
        }
        private async Task SaveUserToFirestore(UserModel userModel, string userUid)
        {
            DocumentReference docRef = _firestoreDb.Collection("users").Document(userUid);
            await docRef.SetAsync(userModel);
        }
        public async Task<UserModel> GetUserProfile(string userUid)
        {
            try
            {
                if (client == null)
                {
                    client = new FireSharp.FirebaseClient(config);
                }

                FirebaseResponse response = client.Get($"User/{userUid}");

                if (response.StatusCode == System.Net.HttpStatusCode.OK && !string.IsNullOrEmpty(response.Body))
                {
                    var user = JsonConvert.DeserializeObject<UserModel>(response.Body);
                    if (user != null && user.Uid == userUid)  // Verify the UID matches
                    {
                        return user;
                    }
                }

                _logger.LogWarning($"No valid profile found for user {userUid}");
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error fetching user profile: {ex.Message}");
                return null;
            }
        }

        public bool IsIncompleteProfile(UserModel user)
        {
            return user == null ||
                   string.IsNullOrEmpty(user.Name) ||
                   string.IsNullOrEmpty(user.Surname) ||
                   string.IsNullOrEmpty(user.Address) ||
                   user.DOB == null ||
                   string.IsNullOrEmpty(user.Email) ||
                   string.IsNullOrEmpty(user.Uid);
        }

        [HttpGet]
        public async Task<IActionResult> Details(string id)
        {
            try
            {
                var userUid = User.FindFirst("user_id")?.Value;

                if (string.IsNullOrEmpty(id) || string.IsNullOrEmpty(userUid))
                {
                    _logger.LogWarning("Missing user ID in Details action");
                    return RedirectToAction("Login", "Home");
                }

                // Security check
                if (id != userUid)
                {
                    _logger.LogWarning($"Unauthorized access attempt to profile {id} by user {userUid}");
                    return Forbid();
                }

                if (client == null)
                {
                    client = new FireSharp.FirebaseClient(config);
                }

                var user = await GetUserProfile(id);
                if (user == null)
                {
                    _logger.LogWarning($"No profile found for user {id}");
                    return RedirectToAction(nameof(Create));
                }

                // If we have a success message, it will be displayed in the view
                ViewBag.SuccessMessage = TempData["SuccessMessage"]?.ToString();

                return View(user);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in Details action: {ex.Message}");
                TempData["ErrorMessage"] = "Error loading profile details.";
                return RedirectToAction("Index", "Home");
            }
        }


        [HttpGet]
        public async Task<IActionResult> Edit(string id)
        {
            try
            {
                var userUid = User.FindFirst("user_id")?.Value;

                // Security check
                if (id != userUid)
                {
                    return Forbid();
                }

                if (client == null)
                {
                    client = new FireSharp.FirebaseClient(config);
                }

                var user = await GetUserProfile(id);
                if (user == null)
                {
                    return RedirectToAction(nameof(Create));
                }

                return View(user);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in Edit GET: {ex.Message}");
                TempData["ErrorMessage"] = "Error loading profile for editing.";
                return RedirectToAction(nameof(Details), new { id = id });
            }
        }


        [HttpPost]
        public async Task<IActionResult> Edit(UserModel userModel)
        {
            try
            {
                var userUid = User.FindFirst("user_id")?.Value;

                // Security check
                if (userModel.Uid != userUid)
                {
                    return Forbid();
                }

                if (client == null)
                {
                    client = new FireSharp.FirebaseClient(config);
                }

                // Get existing user to preserve unchanged fields
                var existingUser = await GetUserProfile(userUid);
                if (existingUser == null)
                {
                    return RedirectToAction(nameof(Create));
                }

                // Preserve critical fields
                userModel.Email = existingUser.Email;
                userModel.Uid = userUid;
                userModel.ImageUrl = existingUser.ImageUrl; // Preserve existing image if not updating

                // Update in Realtime Database
                FirebaseResponse response = client.Update($"User/{userUid}", userModel);

                if (response.StatusCode != System.Net.HttpStatusCode.OK)
                {
                    ModelState.AddModelError(string.Empty, "Failed to update profile in database");
                    return View(userModel);
                }

                // Update in Firestore
                try
                {
                    await SaveUserToFirestore(userModel, userUid);
                }
                catch (Exception firestoreEx)
                {
                    _logger.LogError($"Firestore update failed: {firestoreEx.Message}");
                    // Continue even if Firestore fails as we have updated Realtime DB
                }

                TempData["SuccessMessage"] = "Profile updated successfully!";

                // Explicitly redirect to Details with the user's ID
                return RedirectToAction(nameof(Details), new { id = userUid });
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in Edit POST: {ex.Message}");
                ModelState.AddModelError(string.Empty, $"Error updating profile: {ex.Message}");
                return View(userModel);
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Delete(UserModel userModel)
        {
            try
            {
                var userUid = User.FindFirst("user_id")?.Value;

                // Security check
                if (userModel.Uid != userUid)
                {
                    return Forbid();
                }

                if (client == null)
                {
                    client = new FireSharp.FirebaseClient(config);
                }

                // 1. Delete from Realtime Database
                var response = await client.DeleteAsync($"User/{userUid}");
                if (response.StatusCode != System.Net.HttpStatusCode.OK)
                {
                    throw new Exception("Failed to delete profile from Realtime Database");
                }

                // 2. Delete from Firestore
                try
                {
                    DocumentReference docRef = _firestoreDb.Collection("users").Document(userUid);
                    await docRef.DeleteAsync();
                }
                catch (Exception ex)
                {
                    _logger.LogError($"Error deleting from Firestore: {ex.Message}");
                    // Continue with auth deletion even if Firestore delete fails
                }

                // 3. Delete from Firebase Authentication using Admin SDK
                try
                {
                    await FirebaseAdmin.Auth.FirebaseAuth.DefaultInstance.DeleteUserAsync(userUid);
                }
                catch (FirebaseAdmin.Auth.FirebaseAuthException authEx)
                {
                    _logger.LogError($"Error deleting Firebase auth: {authEx.Message}");
                    // If the user is already deleted or doesn't exist, we can continue
                    if (authEx.AuthErrorCode != AuthErrorCode.UserNotFound)
                    {
                        throw new Exception("Failed to delete authentication credentials");
                    }
                }

                // 4. Sign out the user
                await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

                TempData["SuccessMessage"] = "Your profile and account have been successfully deleted.";
                return RedirectToAction("Index", "Home");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in Delete POST: {ex.Message}");
                ModelState.AddModelError(string.Empty, "Error deleting profile. Please try again.");
                return View(userModel);
            }
        }

        [HttpGet]
        public async Task<IActionResult> Delete(string id)
        {
            try
            {
                var userUid = User.FindFirst("user_id")?.Value;

                if (string.IsNullOrEmpty(id) || string.IsNullOrEmpty(userUid))
                {
                    return RedirectToAction("Login", "Home");
                }

                // Security check
                if (id != userUid)
                {
                    _logger.LogWarning($"Unauthorized delete attempt for profile {id} by user {userUid}");
                    return Forbid();
                }

                var user = await GetUserProfile(id);
                if (user == null)
                {
                    TempData["ErrorMessage"] = "Profile not found.";
                    return RedirectToAction("Index", "Home");
                }

                return View(user);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in Delete GET: {ex.Message}");
                TempData["ErrorMessage"] = "Error loading profile for deletion.";
                return RedirectToAction("Index", "Home");
            }
        }

        public ActionResult ForgotPassword()
        {
            return View();
        }

        // Handle form submission for password reset
        [HttpPost]
        public async Task<ActionResult> ForgotPassword(string email)
        {
            if (string.IsNullOrEmpty(email))
            {
                ViewBag.Message = "Please enter a valid email address.";
                return View();
            }

            try
            {
                // Firebase endpoint to send password reset email
                var requestUri = $"https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key=AIzaSyDMUZwnk0UUjYYkTO4n88vAGq2KayiP5kE";

                var requestData = new
                {
                    requestType = "PASSWORD_RESET",
                    email = email
                };

                // Send the request to Firebase
                var response = await client1.PostAsJsonAsync(requestUri, requestData);

                if (response.IsSuccessStatusCode)
                {
                    ViewBag.Message = "Password reset email sent. Please check your inbox.";
                }
                else
                {
                    var responseBody = await response.Content.ReadAsStringAsync();
                    dynamic jsonResponse = JsonConvert.DeserializeObject(responseBody);

                    // Get the error message from Firebase's response
                    string errorMessage = jsonResponse?.error?.message ?? "Error sending password reset email.";
                    ViewBag.Message = errorMessage;
                }
            }
            catch (Exception ex)
            {
                ViewBag.Message = $"Error: {ex.Message}";
            }

            return View();
        }

    }

    public class UserProfileAttribute : ActionFilterAttribute
        {
            public override void OnActionExecuting(ActionExecutingContext context)
            {
               if (context.Controller is UserController userController)
               {
                  var userUid = context.HttpContext.User.FindFirst("user_id")?.Value;
                    if (!string.IsNullOrEmpty(userUid))
                    {
                       var user = userController.GetUserProfile(userUid).Result;
                       context.HttpContext.Items["IsProfileCreated"] = user != null && !userController.IsIncompleteProfile(user);
                    }
               }

               base.OnActionExecuting(context);
            }
        }
}
