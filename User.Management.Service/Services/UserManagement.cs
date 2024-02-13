using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
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

    public async Task<ApiResponse<CreateUserResponse>> CreateUserWithTokenAsync(RegisterUser registerUser)
    {
        //Check User Exist 
        var userExist = await _userManager.FindByEmailAsync(registerUser.Email);
        if (userExist != null)
        {
            return new ApiResponse<CreateUserResponse>
                { IsSuccess = false, StatusCode = 403, Message = "User already exists!" };
        }

        ApplicationUser user = new()
        {
            Email = registerUser.Email,
            SecurityStamp = Guid.NewGuid().ToString(),
            UserName = registerUser.Username,
            TwoFactorEnabled = true
        };
        var result = await _userManager.CreateAsync(user, registerUser.Password);
        if (result.Succeeded)
        {
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            return new ApiResponse<CreateUserResponse>
            {
                Response = new CreateUserResponse() { User = user, Token = token }, IsSuccess = true, StatusCode = 201,
                Message = "User Created"
            };
        }
        else
        {
            return new ApiResponse<CreateUserResponse>
                { IsSuccess = false, StatusCode = 500, Message = "User Failed to Create" };
        }
    } //end of CreateUserWithTokenAsync

    public async Task<ApiResponse<LoginOtpResponse>> GetOtpByLoginAsync(LoginModel loginModel)
    {
        var user = await _userManager.FindByNameAsync(loginModel.UserName!);
        if (user != null)
        {
            await _signInManager.SignOutAsync();
            await _signInManager.PasswordSignInAsync(user, loginModel.Password!, false, true);
            if (user.TwoFactorEnabled)
            {
                var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");
                return new ApiResponse<LoginOtpResponse>
                {
                    Response = new LoginOtpResponse()
                    {
                        User = user,
                        Token = token,
                        IsTwoFactorEnabled = user.TwoFactorEnabled
                    },
                    IsSuccess = true,
                    StatusCode = 200,
                    Message = $"OTP send to the email {user.Email}"
                };
            }
            else
            {
                return new ApiResponse<LoginOtpResponse>
                {
                    Response = new LoginOtpResponse()
                    {
                        User = user,
                        Token = string.Empty,
                        IsTwoFactorEnabled = user.TwoFactorEnabled
                    },
                    IsSuccess = true,
                    StatusCode = 200,
                    Message = $"2FA is not enabled"
                };
            }
        }
        else
        {
            return new ApiResponse<LoginOtpResponse>
            {
                IsSuccess = false,
                StatusCode = 404,
                Message = "User not found"
            };
        }
    } //end of GetOtpByLoginAsync

    public async Task<ApiResponse<LoginResponse>> GetJwtTokenAsync(ApplicationUser user)
    {
        var authClaims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, user.UserName),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        };

        var userRoles = await _userManager.GetRolesAsync(user);
        foreach (var role in userRoles)
        {
            authClaims.Add(new Claim(ClaimTypes.Role, role));
        }

        var jwtToken = GetToken(authClaims); //access token
        var refreshToken = GenerateRefreshToken();
        _ = int.TryParse(_configuration["JWT:RefreshTokenValidity"], out int RefreshTokenValidityInDays);

        user.RefreshToken = refreshToken;
        user.RefreshTokenExpiry = DateTime.UtcNow.AddDays(RefreshTokenValidityInDays);

        await _userManager.UpdateAsync(user);

        return new ApiResponse<LoginResponse>
        {
            Response = new LoginResponse()
            {
                AccessToken = new TokenType()
                {
                    Token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                    ExpiryTokenDate = jwtToken.ValidTo
                },
                RefreshToken = new TokenType()
                {
                    Token = user.RefreshToken,
                    ExpiryTokenDate = (DateTime)user.RefreshTokenExpiry
                }
            },

            IsSuccess = true,
            StatusCode = 200,
            Message = "Token created"
        };
    }

    public async Task<ApiResponse<LoginResponse>> LoginUserWithJWTokenAsync(string otp, string userName)
    {
        var user = await _userManager.FindByNameAsync(userName);
        var signIn = await _signInManager.TwoFactorSignInAsync("Email", otp, false, false);
        if (signIn.Succeeded)
        {
            if (user != null)
            {
                return await GetJwtTokenAsync(user);
            }
        }
        return new ApiResponse<LoginResponse>
        {
            IsSuccess = false,
            StatusCode = 400,
            Message = "Login failed"
        };
        
    }//end of LoginUserWithJWTokenAsync

    public async Task<ApiResponse<LoginResponse>> RenewAccessTokenAsync(LoginResponse tokens)
    {
        var accessToken = tokens.AccessToken;
        var refreshToken = tokens.RefreshToken;
        var principal = GetClaimsPrincipal(accessToken.Token);
        var user = await _userManager.FindByNameAsync(principal.Identity.Name);
        if (refreshToken.Token != user.RefreshToken && refreshToken.ExpiryTokenDate <= DateTime.Now)
        {
            return new ApiResponse<LoginResponse>
            {
                IsSuccess = false,
                StatusCode = 400,
                Message = "Token invalid or expired"
            };
        }
        var response = await GetJwtTokenAsync(user);
        return response;
    }//end of RenewAccessTokenAsync
    
    #region PrivateMethods
    private JwtSecurityToken GetToken(List<Claim> authClaims)
    {
        var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
        _ = int.TryParse(_configuration["JWT:TokenValidityInMinutes"], out int tokenValidityInMinutes);
        var expirationTimeUtc = DateTime.UtcNow.AddMinutes(tokenValidityInMinutes);
        var localTimeZone = TimeZoneInfo.Local;
        var expirationTimeInLocalTimeZone = TimeZoneInfo.ConvertTimeFromUtc(expirationTimeUtc, localTimeZone);

        var token = new JwtSecurityToken(
            issuer: _configuration["JWT:ValidIssuer"],
            audience: _configuration["JWT:ValidAudience"],
            expires: expirationTimeInLocalTimeZone,
            claims: authClaims,
            signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
        );

        return token;
    }//end of GetToken

    private string GenerateRefreshToken()
    {
        var randomNumber = new Byte[64];
        var range = RandomNumberGenerator.Create();
        range.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }//end of GenerateRefreshToken

    private ClaimsPrincipal GetClaimsPrincipal(string accessToken)
    {
        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = false,
            ValidateIssuer = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"])),
            ValidateLifetime = false
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var principal =
            tokenHandler.ValidateToken(accessToken, tokenValidationParameters, out SecurityToken securityToken);

        return principal;
    }//end of GetClaimsPrincipal
    #endregion
} //end of class