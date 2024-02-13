namespace User.Management.API.Models;

public class Response
{
    public bool IsSuccess { get; set; }
    public string? Message { get; set; }
    public int Status { get; set; }
}