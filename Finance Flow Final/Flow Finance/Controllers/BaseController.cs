using Flow_Finance.Models;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;

namespace Flow_Finance.Controllers
{
    public abstract class BaseController : Controller
    {
        protected readonly ILogger<BaseController> _logger;

        protected BaseController(ILogger<BaseController> logger)
        {
            _logger = logger;
        }

        protected IActionResult HandleError(Exception ex, string customMessage = null)
        {
            var errorModel = new ErrorViewModel
            {
                RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier,
                ErrorMessage = customMessage ?? ex.Message
            };

            // Log the error
            _logger.LogError(ex, "An error occurred: {ErrorMessage}", ex.Message);

            return View("Error", errorModel);
        }
    }
}
