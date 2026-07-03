using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Samples.KeyRotationWithEntityFramework.Migrations
{
    /// <inheritdoc />
    public partial class KeyRotation_V1 : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "SigningKeySets",
                columns: table => new
                {
                    KeySetId = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    ConcurrencyTimestamp = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SigningKeySets", x => x.KeySetId);
                });

            migrationBuilder.CreateTable(
                name: "SigningKeys",
                columns: table => new
                {
                    KeyId = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    KetSetId = table.Column<string>(type: "nvarchar(450)", nullable: true),
                    ActiveFrom = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    ActiveTo = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    KeyMaterial = table.Column<string>(type: "nvarchar(max)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SigningKeys", x => x.KeyId);
                    table.ForeignKey(
                        name: "FK_SigningKeys_SigningKeySets_KetSetId",
                        column: x => x.KetSetId,
                        principalTable: "SigningKeySets",
                        principalColumn: "KeySetId");
                });

            migrationBuilder.CreateIndex(
                name: "IX_SigningKeys_KetSetId",
                table: "SigningKeys",
                column: "KetSetId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "SigningKeys");

            migrationBuilder.DropTable(
                name: "SigningKeySets");
        }
    }
}
