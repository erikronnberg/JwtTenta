using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

using AutoMapper;

using JwtTenta.Data;
using JwtTenta.Models;

using Microsoft.AspNetCore.Identity;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace JwtTenta.Services
{
    public interface IAccountService
    {
        Task<AuthenticateResponse> Authenticate(AuthenticateRequest model);
        Task<AuthenticateResponse> RefreshToken(string token);
        Task RevokeToken(string token);
        Task<AccountResponse> RegisterEmployee(RegisterRequest model);
        Task<AccountResponse> RegisterAdmin(RegisterRequest model);
        Task<AccountResponse> UpdateUser(UpdateRequest model, ClaimsPrincipal user);
        Task<bool> DeleteUser(string username);
        Task<IEnumerable<AccountResponse>> GetAllUsers();
        Task<bool> VerifyToken(string username, string token);
    }

    public class AccountService : IAccountService
    {
        private readonly IMapper mapper;
        private readonly IConfiguration configuration;
        private readonly UserManager<Account> userManager;
        private readonly RoleManager<IdentityRole> roleManager;
        private readonly NorthwindContext context;

        public AccountService(IMapper _mapper, IConfiguration _configuration, UserManager<Account> _userManager, RoleManager<IdentityRole> _roleManager, NorthwindContext _context)
        {
            userManager = _userManager;
            mapper = _mapper;
            configuration = _configuration;
            roleManager = _roleManager;
            context = _context;
        }

        public async Task<bool> VerifyToken(string username, string token)
        {
            var user = await userManager.FindByNameAsync(username);
            if (token != "Bearer " + user.JwtToken)
                return false;

            return true;
        }

        public async Task<AuthenticateResponse> Authenticate(AuthenticateRequest model)
        {
            var account = await userManager.FindByEmailAsync(model.Email);

            if (account == null || await userManager.CheckPasswordAsync(account, model.Password) == false)
                return new AuthenticateResponse { Success = false, ErrorMessage = "User could not be found" };

            // authentication successful so generate jwt and refresh tokens
            var jwtToken = await generateJwtToken(account);
            var refreshToken = generateRefreshToken();

            // save refresh token
            account.RefreshTokens.Add(refreshToken);
            account.JwtToken = jwtToken;

            var result = await userManager.UpdateAsync(account);
            if (!result.Succeeded)
                return new AuthenticateResponse { Success = false, ErrorMessage = "User could not be authenticated" };

            var response = mapper.Map<AuthenticateResponse>(account);
            response.JwtToken = jwtToken;
            response.RefreshToken = refreshToken.Token;
            response.Success = true;
            return response;
        }

        public async Task<AccountResponse> RegisterEmployee(RegisterRequest model)
        {
            var employeeExists = userManager.Users.Where(x => x.EmployeeID == model.EmployeeID).Any();
            var userExists = await userManager.FindByNameAsync(model.Username);

            if (userExists != null || employeeExists)
                return new AccountResponse { Success = false, ErrorMessage = "User already exists" };

            string query = @"Select COUNT(*) FROM Employees WHERE EmployeeID = @EmployeeID";
            using (SqlConnection connection = new SqlConnection(configuration.GetConnectionString("NorthwindContext")))
            {
                SqlCommand command = new SqlCommand(query, connection);
                await connection.OpenAsync();

                command.Parameters.AddWithValue("@EmployeeID", model.EmployeeID);
                var sqlResult = (int)await command.ExecuteScalarAsync();

                if (sqlResult == 0)
                    return new AccountResponse { Success = false, ErrorMessage = "User already exists with requested EmployeeID" };
            }

            if (!await roleManager.RoleExistsAsync(Role.Employee))
                await roleManager.CreateAsync(new IdentityRole(Role.Employee));

            if (!await roleManager.RoleExistsAsync(Role.Admin))
                await roleManager.CreateAsync(new IdentityRole(Role.Admin));

            var user = mapper.Map<Account>(model);

            if (userManager.Users.Count() == 0)
                await userManager.AddToRoleAsync(user, Role.Admin);

            await userManager.AddToRoleAsync(user, Role.Employee);

            user.Created = DateTime.UtcNow;
            user.RefreshTokens = null;

            var result = await userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
                return new AccountResponse { Success = false, ErrorMessage = "User could not be created" };

            var mapped = mapper.Map<AccountResponse>(user);
            mapped.Success = true;
            return mapped;
        }

        public async Task<AccountResponse> RegisterAdmin(RegisterRequest model)
        {
            var employeeExists = userManager.Users.Where(x => x.EmployeeID == model.EmployeeID);
            var userExists = await userManager.FindByNameAsync(model.Username);

            if (userExists != null || employeeExists.ToList() != null)
                return new AccountResponse { Success = false, ErrorMessage = "User already exists" };

            string query = @"Select * FROM Employees WHERE EmployeeID = @EmployeeID ";
            using (SqlConnection connection = new SqlConnection(configuration.GetConnectionString("NorthwindContext")))
            {
                SqlCommand command = new SqlCommand(query, connection);
                await connection.OpenAsync();

                command.Parameters.AddWithValue("@EmployeeID", model.EmployeeID);
                var sqlResult = await command.ExecuteNonQueryAsync();

                if (sqlResult != -1)
                    return new AccountResponse { Success = false, ErrorMessage = "User with requested EmployeeID already exists" };
            }

            if (!await roleManager.RoleExistsAsync(Role.Admin))
                await roleManager.CreateAsync(new IdentityRole(Role.Admin));

            if (!await roleManager.RoleExistsAsync(Role.Employee))
                await roleManager.CreateAsync(new IdentityRole(Role.Employee));

            var user = mapper.Map<Account>(model);

            await userManager.AddToRoleAsync(user, Role.Employee);
            await userManager.AddToRoleAsync(user, Role.Admin);

            user.Created = DateTime.UtcNow;

            var result = await userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
                return new AccountResponse { Success = false, ErrorMessage = "User could not be created" };

            var mapped = mapper.Map<AccountResponse>(user);
            mapped.Success = true;
            return mapped;
        }

        public async Task<AccountResponse> UpdateUser(UpdateRequest model, ClaimsPrincipal user)
        {
            var userToUpdate = await userManager.FindByNameAsync(model.Username);

            if (userToUpdate == null)
                return new AccountResponse { Success = false, ErrorMessage = "User deos not exists" };

            if (user.Identity.Name != userToUpdate.UserName && user.IsInRole("Admin") == false)
                return new AccountResponse { Success = false, ErrorMessage = "Unauthorized" };

            if (model.Role != null && user.IsInRole("Admin") == false)
                return new AccountResponse { Success = false, ErrorMessage = "Unauthorized" };

            if (model.OldPassword != null && model.NewPassword != null)
            {
                var response = await userManager.ChangePasswordAsync(userToUpdate, model.OldPassword, model.NewPassword);
                if (!response.Succeeded)
                    return new AccountResponse { Success = false, ErrorMessage = "Could not update user" };
            }

            var map = mapper.Map<Account>(model);
            var mappedUser = mapper.Map(map, userToUpdate);

            if (model.Role != null && model.Role == Role.CountryManager || model.Role == Role.VD)
            {
                if (!await roleManager.RoleExistsAsync(model.Role))
                    await roleManager.CreateAsync(new IdentityRole(model.Role));

                await userManager.AddToRoleAsync(mappedUser, model.Role);
            }

            mappedUser.Updated = DateTime.UtcNow;

            var result = await userManager.UpdateAsync(mappedUser);
            if (!result.Succeeded)
                return new AccountResponse { Success = false, ErrorMessage = "Could not update user" };

            var mapped = mapper.Map<AccountResponse>(mappedUser);
            mapped.Success = true;
            return mapped;
        }

        public async Task<bool> DeleteUser(string username)
        {

            var userToDelete = await userManager.FindByNameAsync(username);

            if (userToDelete == null)
                return false;

            var result = await userManager.DeleteAsync(userToDelete);
            if (!result.Succeeded)
                return false;

            return true;
        }

        public async Task<IEnumerable<AccountResponse>> GetAllUsers()
        {
            var users = await userManager.Users.ToListAsync();
            var mappedResult = mapper.Map<IEnumerable<AccountResponse>>(users);
            return mappedResult;
        }

        // helper methods

        public async Task<AuthenticateResponse> RefreshToken(string token)
        {
            var (refreshToken, account) = getRefreshToken(token);

            // replace old refresh token with a new one and save
            var newRefreshToken = generateRefreshToken();
            refreshToken.Revoked = DateTime.UtcNow;
            refreshToken.ReplacedByToken = newRefreshToken.Token;
            account.RefreshTokens.Add(newRefreshToken);
            var result = await userManager.UpdateAsync(account);
            if (!result.Succeeded)
                throw new AppException("Refresh token creation failed, please try again");

            // generate new jwt
            var jwtToken = await generateJwtToken(account);
            account.JwtToken = jwtToken;

            var response = mapper.Map<AuthenticateResponse>(account);
            response.JwtToken = jwtToken;
            response.RefreshToken = newRefreshToken.Token;
            return response;
        }

        public async Task RevokeToken(string token)
        {
            var (refreshToken, account) = getRefreshToken(token);

            // revoke token and save
            refreshToken.Revoked = DateTime.UtcNow;
            var result = await userManager.UpdateAsync(account);
            if (!result.Succeeded)
                throw new AppException("Token revoke failed");
        }

        private (RefreshTokens, Account) getRefreshToken(string token)
        {
            var account = userManager.Users.SingleOrDefault(u => u.RefreshTokens.Any(t => t.Token == token));
            if (account == null)
                throw new AppException("Invalid token");

            var refreshToken = account.RefreshTokens.Single(x => x.Token == token);
            if (!refreshToken.IsActive)
                throw new AppException("Invalid token");

            return (refreshToken, account);
        }

        private async Task<string> generateJwtToken(Account account)
        {
            var roles = await userManager.GetRolesAsync(account);
            var employee = await context.Employees.Where(x => x.EmployeeId == account.EmployeeID).FirstOrDefaultAsync();
            var authClaim = new List<Claim>
            {
                new Claim(ClaimTypes.Name, account.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.Country, employee.Country)
            };

            foreach (var role in roles)
                authClaim.Add(new Claim(ClaimTypes.Role, role));

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWT:Secret"]));
            var tokenDescriptor = new JwtSecurityToken(
                issuer: configuration["JWT:ValidIssuer"],
                audience: configuration["JWT:ValidAudience"],
                expires: DateTime.UtcNow.AddMinutes(30),
                signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature),
                claims: authClaim
            );

            var token = new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);

            return token;
        }

        private RefreshTokens generateRefreshToken()
        {
            return new RefreshTokens
            {
                Token = randomTokenString(),
                Expires = DateTime.UtcNow.AddDays(30),
                Created = DateTime.UtcNow
            };
        }

        private string randomTokenString()
        {
            var randomBytes = new byte[40];
            using (var rngCryptoServiceProvider = new RNGCryptoServiceProvider())
            {
                rngCryptoServiceProvider.GetBytes(randomBytes);
            }
            return BitConverter.ToString(randomBytes).Replace("-", "");
        }
    }
}
