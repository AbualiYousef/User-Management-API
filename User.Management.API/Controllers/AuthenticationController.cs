using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using User.Management.Data.Models;
using User.Management.Service.Models;
using User.Management.Service.Models.Authentication.Login;
using User.Management.Service.Models.Authentication.SignUp;
using User.Management.Service.Services;

namespace User.Management.API.Controllers
{
    [Route("api/Authentication")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IEmailService _emailService;
        private readonly IUserManagement _user;

        public AuthenticationController(UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IEmailService emailService,
            SignInManager<ApplicationUser> signInManager,
            IUserManagement user)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _emailService = emailService;
            _signInManager = signInManager;
            _user = user;
        }

        #region RegisterUser

        [HttpPost]
        [Route("Register")]
        public async Task<IActionResult> Register([FromBody] RegisterUser registerUser)
        {
            var tokenResponse = await _user.CreateUserAsync(registerUser);
            if (tokenResponse.IsSuccess)
            {
                await _user.AssignRoleToUserAsync(registerUser.Roles, tokenResponse.Response.User);
                var confirmationLink = Url.Action("ConfirmEmail", "Authentication",
                    new { tokenResponse.Response.Token, email = registerUser.Email }, Request.Scheme);
                var message = new Message(new[] { registerUser.Email! }, "Email Confirmation Link", confirmationLink!);
                _emailService.SendEmail(message);
                return Ok("User Created Successfully! Please confirm your email to login.");
            }

            return BadRequest(tokenResponse.Message);
        } //end of Register

        [HttpGet("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string token, string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                return BadRequest();
            }

            var result = await _userManager.ConfirmEmailAsync(user, token);
            if (result.Succeeded)
            {
                return Ok("Email Confirmed!");
            }
            else
            {
                return BadRequest("This User does not exist!");
            }
        } //end of ConfirmEmail

        #endregion

        // #region Login
        //
        // [HttpPost]
        // [Route("Login")]
        // public async Task<IActionResult> Login([FromBody] LoginModel loginUser)
        // {
        //     var loginOtpResponse = await _user.GetOtpByLoginAsync(loginUser);
        //     if (loginOtpResponse.Response != null)
        //     {
        //         var user = loginOtpResponse.Response.User;
        //         if (user.TwoFactorEnabled)
        //         {
        //             var token = loginOtpResponse.Response.Token;
        //             var message = new Message(new string[] { user.Email! }, "2FA Code", token);
        //             _emailService.SendEmail(message);
        //             return Ok("Two Factor Authentication is enabled for this user. Please use 2FA code to login.");
        //         }
        //         if (await _userManager.CheckPasswordAsync(user, loginUser.Password!))
        //         {
        //             //Create the claims
        //             var authClaims = new List<Claim>
        //             {
        //                 new Claim(ClaimTypes.Name, user.UserName!),
        //                 new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        //             };
        //             //Get the roles of the user
        //             var userRoles = await _userManager.GetRolesAsync(user);
        //             //Add the roles to the claims
        //             foreach (var role in userRoles)
        //             {
        //                 authClaims.Add(new Claim(ClaimTypes.Role, role));
        //             }
        //
        //             //Create the token
        //             var token = GetToken(authClaims);
        //             //return the token
        //             return Ok(new
        //             {
        //                 token = new JwtSecurityTokenHandler().WriteToken(token),
        //                 expiration = token.ValidTo
        //             });
        //         }
        //     }
        //     //return Unauthorized if the user is not found
        //     return Unauthorized();
        // } //end of Login

        // private JwtSecurityToken GetToken(List<Claim> authClaims)
        // {
        //     var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]!));
        //     return new JwtSecurityToken(
        //         issuer: _configuration["JWT:ValidIssuer"],
        //         audience: _configuration["JWT:ValidAudience"],
        //         expires: DateTime.Now.AddHours(1),
        //         claims: authClaims,
        //         signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
        //     );
        // } //end of GetToken
        //
        //
        // [HttpPost]
        // [Route("Login-2FA")]
        // public async Task<IActionResult> LoginWithOTP(string code, string userName)
        // {
        //     var user = await _userManager.FindByNameAsync(userName);
        //     var signIn = await _signInManager.TwoFactorAuthenticatorSignInAsync(code, false, false);
        //     if (!signIn.Succeeded || user == null) return Unauthorized("Invalid Code!");
        //     //Create the claims
        //     var authClaims = new List<Claim>
        //     {
        //         new Claim(ClaimTypes.Name, user.UserName!),
        //         new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        //     };
        //     //Get the roles of the user
        //     var userRoles = await _userManager.GetRolesAsync(user);
        //     //Add the roles to the claims
        //     foreach (var role in userRoles)
        //     {
        //         authClaims.Add(new Claim(ClaimTypes.Role, role));
        //     }
        //
        //     //Create the token
        //     var token = GetToken(authClaims);
        //     //return the token
        //     return Ok(new
        //     {
        //         token = new JwtSecurityTokenHandler().WriteToken(token),
        //         expiration = token.ValidTo
        //     });
        // } //end of LoginWithOTP
        // #endregion

        // #region NotNeeded
        //
        // // [HttpGet]
        // // public async Task<IActionResult> TestEmail()
        // // {
        // //     var message = new Message(new string[]
        // //         { "abualiyousef@outlook.com" }, "Test", "This is the content of the email.");
        // //     _emailService.SendEmail(message);
        // //     return Ok("Email Sent Successfully!");
        // // }
        //
        // #endregion
        //
        // #region ForgotPassword
        //
        // [HttpPost]
        // [AllowAnonymous]
        // [Route("ForgotPassword")]
        // public async Task<IActionResult> ForgotPassword(string email)
        // {
        //     var user = await _userManager.FindByEmailAsync(email);
        //     if (user == null)
        //     {
        //         return BadRequest("Invalid Request");
        //     }
        //
        //     var token = await _userManager.GeneratePasswordResetTokenAsync(user);
        //     var callback = Url.Action("ResetPassword", "Authentication",
        //         new { token, email = user.Email }, Request.Scheme);
        //     var message = new Message(new[] { user.Email! }, "Reset Password Token", callback);
        //     _emailService.SendEmail(message);
        //     return Ok("Reset Password Email Sent!");
        // } //end of ForgotPassword
        //
        // #endregion
        //
        // [HttpGet("ResetPassword")]
        // public IActionResult ResetPassword(string token, string? email)
        // {
        //     var model = new ResetPassword
        //     {
        //         Token = token,
        //         Email = email!
        //     };
        //     return Ok(model);
        // }//end of ResetPassword
        //
        // [HttpPost("ResetPassword")]
        // [AllowAnonymous ]
        // public async Task<IActionResult> ResetPassword(ResetPassword model)
        // {
        //     var user = await _userManager.FindByEmailAsync(model.Email);
        //     if (user == null)
        //     {
        //         return BadRequest("Invalid Request");
        //     }
        //
        //     var resetPassResult = await _userManager.ResetPasswordAsync(user, model.Token, model.Password);
        //     if (resetPassResult.Succeeded)
        //     {
        //         return Ok("Password Reset Successful!");
        //     }
        //     else
        //     {
        //         return BadRequest("Invalid Request");
        //     }
        // }//end of ResetPassword
    } //end of class
} //end of namespace