namespace User.Management.Service.Models.Authentication.User;

public class TokenType
{
    public string Token { get; set; }=null!;
    public DateTime ExpiryTokenDate { get; set; }
}