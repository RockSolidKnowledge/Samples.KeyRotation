using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Samples.KeyRotationWithEntityFramework.Migrations
{
    /// <inheritdoc />
    public partial class KeyRotation_V2 : Migration
    {
        private const string OldKeySetTableName = "SigningKeySets";
        private const string NewKeySetTableName = "RskSecurityKeySets";
        
        private const string OldKeyTableName = "SigningKeys";
        private const string NewKeyTableName = "RskSecurityKeys";
        
        private const string OldKeyTableKeySetIdColumnName = "KetSetId";
        private const string NewKeyTableKeySetIdColumnName = "KeySetId";
        
        private const string OldKeySetId = "Product.KeyRotation.OpenIddict.KeySet";
        private const string NewKeySetId = "Product.KeyRotation.OpenIddict.SigningKeySet";

        private const string OldForeignKeyId = $"FK_{OldKeyTableName}_{OldKeySetTableName}_{OldKeyTableKeySetIdColumnName}";
        private const string NewForeignKeyId = $"FK_{NewKeyTableName}_{NewKeySetTableName}_{NewKeyTableKeySetIdColumnName}";
        
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(name: OldForeignKeyId, table: OldKeyTableName);
            
            migrationBuilder.DropPrimaryKey(name: $"PK_{OldKeySetTableName}", table: OldKeySetTableName);
            migrationBuilder.DropPrimaryKey(name: $"PK_{OldKeyTableName}", table: OldKeyTableName);
            
            migrationBuilder.RenameTable(name: OldKeyTableName, newName: NewKeyTableName);
            migrationBuilder.RenameColumn(name: OldKeyTableKeySetIdColumnName, table: NewKeyTableName, newName: NewKeyTableKeySetIdColumnName);
            migrationBuilder.RenameTable(name: OldKeySetTableName, newName: NewKeySetTableName);
            
            migrationBuilder.UpdateData(
                table: NewKeyTableName,
                keyColumn: NewKeyTableKeySetIdColumnName,
                keyValue: OldKeySetId,
                column: NewKeyTableKeySetIdColumnName,
                value: NewKeySetId);
            
            migrationBuilder.UpdateData(
                table: NewKeySetTableName,
                keyColumn: NewKeyTableKeySetIdColumnName,
                keyValue: OldKeySetId,
                column: NewKeyTableKeySetIdColumnName,
                value: NewKeySetId);
            
            migrationBuilder.Sql($"""
                                  UPDATE [{NewKeyTableName}]
                                  SET KeyId = '{NewKeySetId}.' + KeyId
                                  WHERE KeySetId = '{NewKeySetId}';
                                  """);
            
            migrationBuilder.AddPrimaryKey(name: $"PK_{NewKeySetTableName}", table: NewKeySetTableName, column: "KeySetId");
            migrationBuilder.AddPrimaryKey(name: $"PK_{NewKeyTableName}", table: NewKeyTableName, column: "KeyId");
            
            migrationBuilder.AddForeignKey(
                name: NewForeignKeyId,
                table: NewKeyTableName,
                column: NewKeyTableKeySetIdColumnName,
                principalTable: NewKeySetTableName,
                principalColumn: NewKeyTableKeySetIdColumnName);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(name: NewForeignKeyId, table: NewKeyTableName);
            migrationBuilder.DropPrimaryKey(name: $"PK_{NewKeySetTableName}", table: NewKeySetTableName);
            migrationBuilder.DropPrimaryKey(name: $"PK_{NewKeyTableName}", table: NewKeyTableName);
            
            migrationBuilder.RenameTable(name: NewKeyTableName, newName: OldKeyTableName);
            migrationBuilder.RenameColumn(name: NewKeyTableKeySetIdColumnName, table: OldKeyTableName, newName: OldKeyTableKeySetIdColumnName);
            migrationBuilder.RenameTable(name: NewKeySetTableName, newName: OldKeySetTableName);
            
            migrationBuilder.UpdateData(
                table: OldKeyTableName,
                keyColumn: OldKeyTableKeySetIdColumnName,
                keyValue: NewKeySetId,
                column: OldKeyTableKeySetIdColumnName,
                value: OldKeySetId);
            
            migrationBuilder.UpdateData(
                table: OldKeySetTableName,
                keyColumn: NewKeyTableKeySetIdColumnName,
                keyValue: NewKeySetId,
                column: NewKeyTableKeySetIdColumnName,
                value: OldKeySetId);
            
            migrationBuilder.Sql($"""
                                  UPDATE [{OldKeyTableName}]
                                  SET KeyId = REPLACE(KeyId, '{NewKeySetId}.', '')
                                  WHERE KetSetId = '{OldKeySetId}';
                                  """);
            
            migrationBuilder.AddPrimaryKey(name: $"PK_{OldKeySetTableName}", table: OldKeySetTableName, column: "KeySetId");
            migrationBuilder.AddPrimaryKey(name: $"PK_{OldKeyTableName}", table: OldKeyTableName, column: "KeyId");
            
            migrationBuilder.AddForeignKey(
                name: OldForeignKeyId,
                table: OldKeyTableName,
                column: OldKeyTableKeySetIdColumnName,
                principalTable: OldKeySetTableName,
                principalColumn: NewKeyTableKeySetIdColumnName);
        }
    }
}
