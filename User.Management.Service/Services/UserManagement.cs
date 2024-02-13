using Azure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using User.Management.Data.Models;
using User.Management.Service.Models;
using User.Management.Service.Models.Authentication.Login;
using User.Management.Service.Models.Authentication.SignUp;
using User.Management.Service.Models.Authentication.User;

namespace User.Management.Service.Services;

public class UserManagement : IUserManagement
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly IConfiguration _configuration;

    public UserManagement(UserManager<ApplicationUser> userManager,
        RoleManager<IdentityRole> roleManager,
        SignInManager<ApplicationUser> signInManager,
        IConfiguration configuration)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _signInManager = signInManager;
        _configuration = configuration;
    }

    public async Task<ApiResponse<CreateUserResponse>> CreateUserAsync(RegisterUser registerUser)
    {
        //Check if the user with the same email exists
        var userExists = await _userManager.FindByEmailAsync(registerUser.Email!);
        if (userExists != null)
        {
            return new ApiResponse<CreateUserResponse>
            {
                IsSuccess = false,
                Message = "User with this email already exists!",
                StatusCode = StatusCodes.Status400BadRequest
            };
        }

        //Create a new user
        var user = new ApplicationUser()
        {
            Email = registerUser.Email,
            SecurityStamp = Guid.NewGuid().ToString(),
            UserName = registerUser.Username,
            TwoFactorEnabled = true
        };
        var result = await _userManager.CreateAsync(user, registerUser.Password);
        if (result.Succeeded)
        {
            //Generate token
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            //return the user and the token
            return new ApiResponse<CreateUserResponse>
            {
                Response = new CreateUserResponse()
                {
                    User = user,
                    Token = token
                },
                IsSuccess = true,
                Message = "User created successfully!",
                StatusCode = StatusCodes.Status200OK
            };
        }
        else
        {
            return new ApiResponse<CreateUserResponse>
            {
                IsSuccess = false,
                Message = "User creation failed! Please check user details and try again.",
                StatusCode = StatusCodes.Status500InternalServerError
            };
        }
    } //CreateUserAsync

    public async Task<ApiResponse<List<string>>> AssignRoleToUserAsync(List<string> roles, ApplicationUser user)
    {
        var assignedRoles = new List<string>();
        foreach (var role in roles)
        {
            if (await _roleManager.RoleExistsAsync(role))
            {
                if (!await _userManager.IsInRoleAsync(user, role))
                {
                    await _userManager.AddToRoleAsync(user, role);
                    assignedRoles.Add(role);
                } //end of if
            } //end of if
        } //end of foreach

        return new ApiResponse<List<string>>()
        {
            IsSuccess = true,
            Message = "Roles assigned successfully!",
            StatusCode = StatusCodes.Status500InternalServerError,
            Response = assignedRoles
        };
    } //end of AssignRoleToUserAsync

    public async Task<ApiResponse<LoginOtpResponse>> GetOtpByLoginAsync(LoginModel loginUser)
    {
        var user = await _userManager.FindByNameAsync(loginUser.UserName!);
        if (user == null)
        {
            return new ApiResponse<LoginOtpResponse>
            {
                IsSuccess = false,
                Message = "User does not exist!",
                StatusCode = StatusCodes.Status404NotFound
            };
        }

        await _signInManager.SignOutAsync();
        await _signInManager.PasswordSignInAsync(user, loginUser.Password, false, false);
        if (user.TwoFactorEnabled)
        {
            var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");
            return new ApiResponse<LoginOtpResponse>
            {
                IsSuccess = true,
                Message = "OTP sent successfully!",
                StatusCode = StatusCodes.Status200OK,
                Response = new LoginOtpResponse()
                {
                    User = user,
                    Token = token,
                    ISTwoFactorEnabled = user.TwoFactorEnabled
                }
            };
        }
        else
        {
            return new ApiResponse<LoginOtpResponse>
            {
                IsSuccess = true,
                Message = "Two Factor Authentication is not enabled for this user!",
                StatusCode = 200,
                Response = new LoginOtpResponse()
                {
                    User = user,
                    Token = null!,
                    ISTwoFactorEnabled = user.TwoFactorEnabled
                }
            };
        }
    } //end of GetOtpByLoginAsync
} //UserManagement