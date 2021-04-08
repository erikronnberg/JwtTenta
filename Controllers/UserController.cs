using System.Threading.Tasks;

using JwtTenta.Models;
using JwtTenta.Services;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Net.Http.Headers;

namespace UserDataAPIApp.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly IAccountService accountService;

        public UserController(IAccountService _accountService)
        {
            accountService = _accountService;
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> AuthenticateUser([FromBody] AuthenticateRequest model)
        {
            var response = await accountService.Authenticate(model);
            if (!response.Success)
                return BadRequest(response);

            return Ok(response);
        }

        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> RegisterEmployee([FromBody] RegisterRequest model)
        {
            var response = await accountService.RegisterEmployee(model);
            if (!response.Success)
                return BadRequest(response);

            return Ok(response);
        }

        [Authorize(Policy = "RequireAdmin")]
        [HttpPost]
        [Route("register-admin")]
        public async Task<IActionResult> RegisterAdmin([FromBody] RegisterRequest model)
        {
            var username = Request.HttpContext.User.Identity.Name;
            var token = Request.Headers[HeaderNames.Authorization];
            var success = await accountService.VerifyToken(username, token);
            if (!success)
                return Unauthorized();

            var response = await accountService.RegisterAdmin(model);
            if (!response.Success)
                return BadRequest(response);

            return Ok(response);
        }

        [Authorize]
        [HttpPatch]
        [Route("update")]
        public async Task<IActionResult> Update([FromBody] UpdateRequest model)
        {
            var username = Request.HttpContext.User.Identity.Name;
            var token = Request.Headers[HeaderNames.Authorization];
            var success = await accountService.VerifyToken(username, token);
            if (!success)
                return Unauthorized();

            var user = Request.HttpContext.User;
            var response = await accountService.UpdateUser(model, user);
            if (!response.Success)
                return BadRequest(response);

            return Ok(response);
        }

        [Authorize(Policy = "RequireAdmin")]
        [HttpDelete]
        [Route("delete")]
        public async Task<IActionResult> Delete(string username)
        {
            var user = Request.HttpContext.User.Identity.Name;
            var token = Request.Headers[HeaderNames.Authorization];
            var success = await accountService.VerifyToken(user, token);
            if (!success)
                return Unauthorized();

            var response = await accountService.DeleteUser(username);
            if (!response)
                return BadRequest();

            return Ok();
        }

        [Authorize(Policy = "RequireAdminOrVD")]
        [HttpGet]
        [Route("get-all-users")]
        public async Task<IActionResult> GetAll()
        {
            var username = Request.HttpContext.User.Identity.Name;
            var token = Request.Headers[HeaderNames.Authorization];
            var success = await accountService.VerifyToken(username, token);
            if (!success)
                return Unauthorized();


            var response = await accountService.GetAllUsers();
            return Ok(response);
        }

        [HttpPost]
        [Route("refresh-token")]
        public async Task<IActionResult> RefreshToken()
        {
            string input = Request.Headers[HeaderNames.Authorization];
            var token = input.Split(" ");
            var response = await accountService.RefreshToken(token[1]);
            return Ok(response);
        }
    }
}
