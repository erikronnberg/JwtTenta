using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

using AutoMapper;

using JwtTenta.Data;
using JwtTenta.Models;
using JwtTenta.Models.Response;
using JwtTenta.Services;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Net.Http.Headers;

namespace JwtTenta.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class OrderController : ControllerBase
    {
        private readonly NorthwindContext context;
        private readonly UserManager<Account> userManager;
        private readonly IMapper mapper;
        private readonly IAccountService accountService;

        public OrderController(NorthwindContext _context, UserManager<Account> _userManager, IMapper _mapper, IAccountService _accountService)
        {
            context = _context;
            userManager = _userManager;
            mapper = _mapper;
            accountService = _accountService;
        }

        [Authorize(Policy = "ElevatedRights")]
        [Route("get-all-orders")]
        [HttpGet]
        public async Task<ActionResult<IEnumerable<OrderResponse>>> GetAllOrders()
        {
            var username = Request.HttpContext.User.Identity.Name;
            var token = Request.Headers[HeaderNames.Authorization];
            var success = await accountService.VerifyToken(username, token);
            if (!success)
                return Unauthorized();

            var user = await userManager.FindByNameAsync(username);

            if (await userManager.IsInRoleAsync(user, Role.CountryManager) == true)
            {
                var employee = await context.Employees.Where(x => x.EmployeeId == user.EmployeeID).FirstOrDefaultAsync();
                var cmResult = await context.Orders.Where(x => x.ShipCountry == employee.Country).ToListAsync();
                if (cmResult == null)
                    return StatusCode(StatusCodes.Status404NotFound);

                var mapped = mapper.Map<IEnumerable<OrderResponse>>(cmResult);
                return Ok(mapped);
            }

            var result = await context.Orders.ToListAsync();
            if (result == null)
                return StatusCode(StatusCodes.Status404NotFound);

            var response = mapper.Map<IEnumerable<OrderResponse>>(result);
            return Ok(response);
        }

        [Authorize(Policy = "ElevatedRights")]
        [Route("get-orders-by-country")]
        [HttpGet]
        public async Task<ActionResult<IEnumerable<OrderResponse>>> GetCountryOrders()
        {
            var username = Request.HttpContext.User.Identity.Name;
            var token = Request.Headers[HeaderNames.Authorization];
            var country = Request.HttpContext.User.Claims.Where(x => x.Type == ClaimTypes.Country).FirstOrDefault();
            var success = await accountService.VerifyToken(username, token);
            if (!success)
                return Unauthorized();

            var user = await userManager.FindByNameAsync(HttpContext.User.Identity.Name);

            if (await userManager.IsInRoleAsync(user, Role.CountryManager) == true)
            {
                var employee = await context.Employees.Where(x => x.EmployeeId == user.EmployeeID).FirstOrDefaultAsync();
                var cmResult = await context.Orders.Where(x => x.ShipCountry == employee.Country).ToListAsync();
                if (cmResult == null)
                    return StatusCode(StatusCodes.Status404NotFound);

                var mapped = mapper.Map<IEnumerable<OrderResponse>>(cmResult);
                return Ok(mapped);
            }

            var result = await context.Orders.Where(x => x.ShipCountry == country.Value).ToListAsync();
            if (result == null)
                return StatusCode(StatusCodes.Status404NotFound);

            var response = mapper.Map<IEnumerable<OrderResponse>>(result);
            return Ok(response);
        }

        [Authorize]
        [Route("get-my-orders")]
        [HttpGet]
        public async Task<ActionResult<IEnumerable<OrderResponse>>> GetMyOrders(int id)
        {
            var username = Request.HttpContext.User.Identity.Name;
            var token = Request.Headers[HeaderNames.Authorization];
            var success = await accountService.VerifyToken(username, token);
            if (!success)
                return Unauthorized();

            var user = await userManager.FindByNameAsync(HttpContext.User.Identity.Name);

            if (await userManager.IsInRoleAsync(user, Role.Admin) == false && await userManager.IsInRoleAsync(user, Role.VD) == false)
            {
                var employee = await context.Employees.Where(x => x.EmployeeId == user.EmployeeID).FirstOrDefaultAsync();
                var cmResult = await context.Orders.Where(x => x.EmployeeId == employee.EmployeeId).ToListAsync();
                if (cmResult == null)
                    return StatusCode(StatusCodes.Status404NotFound);

                var mapped = mapper.Map<IEnumerable<OrderResponse>>(cmResult);
                return Ok(mapped);
            }

            var result = await context.Orders.Where(x => x.EmployeeId == id).ToListAsync();
            if (result == null)
                return StatusCode(StatusCodes.Status404NotFound);

            var response = mapper.Map<IEnumerable<OrderResponse>>(result);
            return Ok(response);
        }
    }
}