using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace User.Management.API.Migrations
{
    /// <inheritdoc />
    public partial class RolesSeeded : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { "3d29fe3f-1a39-4624-8abf-7ff72d26fb1a", "1", "Admin", "ADMIN" },
                    { "8780a48d-ef16-4bfe-a65d-d2fbe036512f", "3", "HR", "HR" },
                    { "ddea00d6-1489-47b3-a196-ec3ebb3683fd", "2", "User", "USER" }
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "3d29fe3f-1a39-4624-8abf-7ff72d26fb1a");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "8780a48d-ef16-4bfe-a65d-d2fbe036512f");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "ddea00d6-1489-47b3-a196-ec3ebb3683fd");
        }
    }
}
