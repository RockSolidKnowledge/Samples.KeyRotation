BEGIN TRANSACTION;
GO

CREATE TABLE [SigningKeySets] (
    [KeySetId] nvarchar(450) NOT NULL,
    [Timestamp] datetime2 NOT NULL,
    CONSTRAINT [PK_SigningKeySets] PRIMARY KEY ([KeySetId])
);
GO

CREATE TABLE [SigningKeys] (
    [KeyId] nvarchar(450) NOT NULL,
    [KetSetId] nvarchar(450) NULL,
    [ActiveFrom] datetime2 NOT NULL,
    [ActiveTo] datetime2 NOT NULL,
    [KeyMaterial] nvarchar(max) NOT NULL,
    CONSTRAINT [PK_SigningKeys] PRIMARY KEY ([KeyId]),
    CONSTRAINT [FK_SigningKeys_SigningKeySets_KetSetId] FOREIGN KEY ([KetSetId]) REFERENCES [SigningKeySets] ([KeySetId])
);
GO

CREATE INDEX [IX_SigningKeys_KetSetId] ON [SigningKeys] ([KetSetId]);
GO

COMMIT;
GO

