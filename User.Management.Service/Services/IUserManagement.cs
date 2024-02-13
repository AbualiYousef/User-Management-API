using User.Management.Data.Models;
using User.Management.Service.Models;
using User.Management.Service.Models.Authentication.Login;
using User.Management.Service.Models.Authentication.SignUp;
using User.Management.Service.Models.Authentication.User;

namespace User.Management.Service.Services;

public interface IUserManagement
{
    Task<ApiResponse<CreateUserResponse>> CreateUserAsync(RegisterUser registerUser);
    Task<ApiResponse<List<string>>> AssignRoleToUserAsync(List<string> roles,ApplicationUser user);
    
    Task<ApiResponse<LoginOtpResponse>> GetOtpByLoginAsync(LoginModel loginModel);

}