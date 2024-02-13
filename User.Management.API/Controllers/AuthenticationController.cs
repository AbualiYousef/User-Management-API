using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using User.Management.API.Models;
using User.Management.Data.Models;
using User.Management.Service.Models;
using User.Management.Service.Models.Authentication.Login;
using User.Management.Service.Models.Authentication.SignUp;
using User.Management.Service.Models.Authentication.User;
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
            var tokenResponse = await _user.CreateUserWithTokenAsync(registerUser);
            if (tokenResponse.IsSuccess && tokenResponse.Response != null)
            {
                await _user.AssignRoleToUserAsync(registerUser.Roles!, tokenResponse.Response.User);
                var confirmationLink = Url.Action("ConfirmEmail", "Authentication",
                    new { tokenResponse.Response.Token, email = registerUser.Email! }, Request.Scheme);

                var message = new Message(new string[] { registerUser.Email! },
                    "Confirmation email link", confirmationLink!);
                _emailService.SendEmail(message);
                return StatusCode(StatusCodes.Status200OK,
                    new Response { Status = "Success", Message = "Email Verified Successfully" });
            }

            return StatusCode(StatusCodes.Status500InternalServerError,
                new Response { Message = tokenResponse.Message, IsSuccess = false });
        }

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
                return StatusCode(StatusCodes.Status200OK,
                    new Response { Status = "Success", Message = "Email Confirmed Successfully!" });
            }
            else
            {
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new Response { Status = "Error", Message = "Email Confirmation Failed!" });
            }
        } //end of ConfirmEmail

        #endregion

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel loginModel)
        {
            var loginOtpResponse = await _user.GetOtpByLoginAsync(loginModel);
            if (loginOtpResponse.Response == null) return Unauthorized();
            var user = loginOtpResponse.Response.User;
            if (!await _userManager.CheckPasswordAsync(user, loginModel.Password!)) return Unauthorized();
            if (user.TwoFactorEnabled)
            {
                var token = loginOtpResponse.Response.Token;
                var message = new Message(new string[] { user.Email! }, "OTP Confirmation", token);
                _emailService.SendEmail(message);

                return StatusCode(StatusCodes.Status200OK,
                    new Response
                    {
                        IsSuccess = loginOtpResponse.IsSuccess,
                        Status = "Success",
                        Message = $"We have sent an OTP to your Email {user.Email}"
                    });
            }
            var serviceResponse = await _user.GetJwtTokenAsync(user);
            return Ok(serviceResponse);

        } //end of Login

        [HttpPost]
        [Route("login-2FA")]
        public async Task<IActionResult> LoginWithOtp(string code, string userName)
        {
            var jwt = await _user.LoginUserWithJWTokenAsync(code, userName);
            if (jwt.IsSuccess)
            {
                return Ok(jwt);
            }

            return StatusCode(StatusCodes.Status404NotFound,
                new Response { Status = "Success", Message = $"Invalid Code" });
        }


        #region ForgotPassword

        [HttpPost]
        [AllowAnonymous]
        [Route("ForgotPassword")]
        public async Task<IActionResult> ForgotPassword(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                return BadRequest("Invalid Request");
            }

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var callback = Url.Action("ResetPassword", "Authentication",
                new { token, email = user.Email }, Request.Scheme);
            var message = new Message(new[] { user.Email! }, "Reset Password Token", callback);
            _emailService.SendEmail(message);
            return Ok("Reset Password Email Sent!");
        } //end of ForgotPassword

        #endregion

        [HttpGet("ResetPassword")]
        public IActionResult ResetPassword(string token, string? email)
        {
            var model = new ResetPassword
            {
                Token = token,
                Email = email!
            };
            return Ok(model);
        } //end of ResetPassword

        [HttpPost("ResetPassword")]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword(ResetPassword model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                return BadRequest("Invalid Request");
            }

            var resetPassResult = await _userManager.ResetPasswordAsync(user, model.Token, model.Password);
            if (resetPassResult.Succeeded)
            {
                return Ok("Password Reset Successful!");
            }
            else
            {
                return BadRequest("Invalid Request");
            }
        } //end of ResetPassword

        [HttpPost]
        [Route("Refresh-Token")]
        public async Task<IActionResult> RefreshToken(LoginResponse tokens)
        {
            var jwt = await _user.RenewAccessTokenAsync(tokens);
            if (jwt.IsSuccess)
            {
                return Ok(jwt);
            }

            return StatusCode(StatusCodes.Status404NotFound,
                new Response { Status = "Success", Message = $"Invalid Code" });
        } //end of RefreshToken

        #region NotNeeded

        // [HttpGet]
        // public async Task<IActionResult> TestEmail()
        // {
        //     var message = new Message(new string[]
        //         { "abualiyousef@outlook.com" }, "Test", "This is the content of the email.");
        //     _emailService.SendEmail(message);
        //     return Ok("Email Sent Successfully!");
        // }

        #endregion
    } //end of class
} //end of namespace