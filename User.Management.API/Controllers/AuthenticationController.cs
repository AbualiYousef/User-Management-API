using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using User.Management.API.Models;
using User.Management.API.Models.Authentication.Login;
using User.Management.API.Models.Authentication.SignUp;
using User.Management.Service.Models;
using User.Management.Service.Services;   

namespace User.Management.API.Controllers
{
    [Route("api/Authentication")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IEmailService _emailService;
        private readonly IConfiguration _configuration;

        public AuthenticationController(UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IEmailService emailService,
            IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _emailService = emailService;
            _configuration = configuration;
        }


        #region RegisterUser
        
        [HttpPost]
        [Route("Register")]
        public async Task<IActionResult> Register([FromBody] RegisterUser registerUser, string role)
        {
            //Check if the user with the same email exists
            var userExists = await _userManager.FindByEmailAsync(registerUser.Email!);
            if (userExists != null)
            {
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new Response { Status = "Error", Message = "User already exists!" });
            }
            //Create a new user
            var user = new IdentityUser()
            {
                Email = registerUser.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = registerUser.Username
            };
            if (await _roleManager.RoleExistsAsync(role))
            {
                var result = await _userManager.CreateAsync(user, registerUser.Password!);
                if(!result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status500InternalServerError,
                        new Response { Status = "Error", Message = "User creation failed! Please check user details and try again." });
                }
                 //Assign Role to the user
                 await _userManager.AddToRoleAsync(user, role);
                 //Add token to verify email
                 var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                 var confirmationLink = Url.Action("ConfirmEmail", "Authentication",
                     new { token, email = user.Email }, Request.Scheme);
                 var message = new Message(new[] { user.Email!}, "Email Confirmation Link", confirmationLink!);
                 _emailService.SendEmail(message);
                 //return the response
                 return Ok(new Response { Status = "Success", 
                     Message = "User created successfully! Please confirm your email by clicking on the link sent to your email address." });
            }
            else
            {
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new Response { Status = "Error", Message = "Role does not exist!" });
            }
        }//end of Register
        
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
        }//end of ConfirmEmail
        #endregion

        #region Login
        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login([FromBody] LoginModel loginUser)
        {
            //Check if the user exists
            var user = await _userManager.FindByNameAsync(loginUser.UserName!);
            if (user != null && await _userManager.CheckPasswordAsync(user, loginUser.Password!))
            {
                //Create the claims
                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName!),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };
                //Get the roles of the user
                var userRoles = await _userManager.GetRolesAsync(user);
                //Add the roles to the claims
                foreach (var role in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, role));
                }
                //Create the token
                var token = GetToken(authClaims);
                //return the token
                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token),
                    expiration = token.ValidTo
                });
            }
            //return Unauthorized if the user is not found
            return Unauthorized();
        }//end of Login

        private JwtSecurityToken GetToken(List<Claim> authClaims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]!));
            return new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddHours(1),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
            );
        }//end of GetToken
        
        #endregion
        
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

    }//end of class
}//end of namespace