using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using FireSharp.Interfaces;
using FireSharp.Response;
using Flow_Finance.Models;
using Newtonsoft.Json;
using System.Collections.Generic;
using FirebaseAdmin;
using Firebase.Auth;
using FirebaseAdmin.Auth;
using Google.Apis.Auth.OAuth2;
using System.Net.Http.Headers;

namespace Flow_Finance.Controllers
{
    [Authorize(Roles = "Admin")]
    public class AdminController : Controller
    {
        private readonly IFirebaseClient _firebaseClient;
        private readonly ILogger<AdminController> _logger;
        private readonly string _firebaseApiKey;

        public AdminController(IFirebaseClient firebaseClient, ILogger<AdminController> logger, IConfiguration configuration)
        {
            _firebaseClient = firebaseClient;
            _logger = logger;
            _firebaseApiKey = configuration.GetValue<string>("Firebase:ApiKey");
        }

        public async Task<IActionResult> Index()
        {
            try
            {
                // Get all users from Firebase
                FirebaseResponse response = await _firebaseClient.GetAsync("User");
                if (response.Body == "null")
                {
                    return View(new List<UserModel>());
                }

                var data = JsonConvert.DeserializeObject<Dictionary<string, UserModel>>(response.Body);
                var users = data?.Values.ToList() ?? new List<UserModel>();

                return View(users);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error fetching users: {ex.Message}");
                TempData["ErrorMessage"] = "Error loading users.";
                return View(new List<UserModel>());
            }
        }

        public async Task<IActionResult> Edit(string id)
        {
            try
            {
                FirebaseResponse response = await _firebaseClient.GetAsync($"User/{id}");
                if (response.Body == "null")
                {
                    TempData["ErrorMessage"] = "User not found.";
                    return RedirectToAction(nameof(Index));
                }

                var user = JsonConvert.DeserializeObject<UserModel>(response.Body);
                return View(user);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error fetching user for edit: {ex.Message}");
                TempData["ErrorMessage"] = "Error loading user details.";
                return RedirectToAction(nameof(Index));
            }
        }

        [HttpPost]
        public async Task<IActionResult> Edit(UserModel user)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return View(user);
                }

                var response = await _firebaseClient.UpdateAsync($"User/{user.Uid}", user);
                if (response.StatusCode == System.Net.HttpStatusCode.OK)
                {
                    TempData["SuccessMessage"] = "User updated successfully.";
                    return RedirectToAction(nameof(Index));
                }

                ModelState.AddModelError("", "Failed to update user.");
                return View(user);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error updating user: {ex.Message}");
                ModelState.AddModelError("", "Error updating user.");
                return View(user);
            }
        }
        [HttpPost]
        public async Task<IActionResult> Delete(string id)
        {
            try
            {
                // Step 1: Delete from Firebase Authentication
                await DeleteUserFromAuthentication(id);

                // Step 2: Delete from Realtime Database
                var dbResponse = await _firebaseClient.DeleteAsync($"User/{id}");
                if (dbResponse.StatusCode == System.Net.HttpStatusCode.OK)
                {
                    TempData["SuccessMessage"] = "User completely deleted from the system.";
                    _logger.LogInformation($"User {id} deleted from Realtime Database");
                }
                else
                {
                    TempData["ErrorMessage"] = "User deleted from authentication but failed to delete from database.";
                    _logger.LogWarning($"Failed to delete user {id} from Realtime Database. Status code: {dbResponse.StatusCode}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in delete operation: {ex.Message}");
                TempData["ErrorMessage"] = "An error occurred while deleting the user.";
            }

            return RedirectToAction(nameof(Index));
        }

        private async Task DeleteUserFromAuthentication(string userId)
        {
            try
            {
                using (var httpClient = new HttpClient())
                {
                    httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Firebase", _firebaseApiKey);
                    var response = await httpClient.DeleteAsync($"https://identitytoolkit.googleapis.com/v1/accounts:{userId}?key={_firebaseApiKey}");
                    if (!response.IsSuccessStatusCode)
                    {
                        _logger.LogError($"Error deleting user {userId} from Firebase Authentication: {response.StatusCode} - {await response.Content.ReadAsStringAsync()}");
                    }
                    else
                    {
                        _logger.LogInformation($"User {userId} deleted from Firebase Authentication");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error deleting user {userId} from Firebase Authentication: {ex.Message}");
            }
        }
    }
}
