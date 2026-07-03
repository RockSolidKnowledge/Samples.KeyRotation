BEGIN TRANSACTION;
GO

ALTER TABLE [SigningKeys] DROP CONSTRAINT [FK_SigningKeys_SigningKeySets_KetSetId];
GO

ALTER TABLE [SigningKeySets] DROP CONSTRAINT [PK_SigningKeySets];
GO

ALTER TABLE [SigningKeys] DROP CONSTRAINT [PK_SigningKeys];
GO

EXEC sp_rename N'[SigningKeys]', N'RskSecurityKeys';
GO

EXEC sp_rename N'[RskSecurityKeys].[KetSetId]', N'KeySetId', N'COLUMN';
GO

EXEC sp_rename N'[SigningKeySets]', N'RskSecurityKeySets';
GO

UPDATE [RskSecurityKeys] SET [KeySetId] = N'Product.KeyRotation.OpenIddict.SigningKeySet'
WHERE [KeySetId] = N'Product.KeyRotation.OpenIddict.KeySet';
SELECT @@ROWCOUNT;

GO

UPDATE [RskSecurityKeySets] SET [KeySetId] = N'Product.KeyRotation.OpenIddict.SigningKeySet'
WHERE [KeySetId] = N'Product.KeyRotation.OpenIddict.KeySet';
SELECT @@ROWCOUNT;

GO

UPDATE [RskSecurityKeys]
SET KeyId = 'Product.KeyRotation.OpenIddict.SigningKeySet.' + KeyId
WHERE KeySetId = 'Product.KeyRotation.OpenIddict.SigningKeySet';
GO

ALTER TABLE [RskSecurityKeySets] ADD CONSTRAINT [PK_RskSecurityKeySets] PRIMARY KEY ([KeySetId]);
GO

ALTER TABLE [RskSecurityKeys] ADD CONSTRAINT [PK_RskSecurityKeys] PRIMARY KEY ([KeyId]);
GO

ALTER TABLE [RskSecurityKeys] ADD CONSTRAINT [FK_RskSecurityKeys_RskSecurityKeySets_KeySetId] FOREIGN KEY ([KeySetId]) REFERENCES [RskSecurityKeySets] ([KeySetId]);
GO

INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
VALUES (N'20251124113053_KeyRotation_V2', N'8.0.22');
GO

COMMIT;
GO


