using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace User.Management.Data.Migrations
{
    /// <inheritdoc />
    public partial class ApplicationUserAdded : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "57dca8b6-b5a7-4f5c-ab80-164fb7ea53e0");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "81db18fc-8e21-45d6-b1e1-b17fc3023cf0");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "f5bdd100-c7c9-4238-9316-dbbbb401f0ed");

            migrationBuilder.AddColumn<DateTime>(
                name: "RefreshToken",
                table: "AspNetUsers",
                type: "datetime2",
                nullable: false,
                defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified));

            migrationBuilder.AddColumn<DateTime>(
                name: "RefreshTokenExpiry",
                table: "AspNetUsers",
                type: "datetime2",
                nullable: false,
                defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified));

            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { "316a96d1-c5f5-4d04-8c8a-6a4bd63d969d", "3", "HR", "HR" },
                    { "9c2f7b9b-2766-475b-aabf-a53eef51d074", "2", "User", "USER" },
                    { "ffa3a955-6e69-4383-ba9f-b75965e3dc54", "1", "Admin", "ADMIN" }
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "316a96d1-c5f5-4d04-8c8a-6a4bd63d969d");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "9c2f7b9b-2766-475b-aabf-a53eef51d074");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "ffa3a955-6e69-4383-ba9f-b75965e3dc54");

            migrationBuilder.DropColumn(
                name: "RefreshToken",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "RefreshTokenExpiry",
                table: "AspNetUsers");

            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { "57dca8b6-b5a7-4f5c-ab80-164fb7ea53e0", "2", "User", "USER" },
                    { "81db18fc-8e21-45d6-b1e1-b17fc3023cf0", "1", "Admin", "ADMIN" },
                    { "f5bdd100-c7c9-4238-9316-dbbbb401f0ed", "3", "HR", "HR" }
                });
        }
    }
}
