BEGIN TRANSACTION;
GO

CREATE TABLE [RskSecurityKeySets]
(
    [KeySetId]             nvarchar(450) NOT NULL,
    [ConcurrencyTimestamp] datetime2     NOT NULL,
    CONSTRAINT [PK_RskSecurityKeySets] PRIMARY KEY ([KeySetId])
);
GO

CREATE TABLE [RskSecurityKeys]
(
    [KeyId]       nvarchar(450)  NOT NULL,
    [KeySetId]    nvarchar(450)  NULL,
    [ActiveFrom]  datetimeoffset NOT NULL,
    [ActiveTo]    datetimeoffset NOT NULL,
    [KeyMaterial] nvarchar(max)  NOT NULL,
    CONSTRAINT [PK_RskSecurityKeys] PRIMARY KEY ([KeyId]),
    CONSTRAINT [FK_RskSecurityKeys_RskSecurityKeySets_KeySetId] FOREIGN KEY ([KeySetId]) REFERENCES [RskSecurityKeySets] ([KeySetId])
);
GO

CREATE INDEX [IX_RskSecurityKeys_KeySetId] ON [RskSecurityKeys] ([KeySetId]);
GO

COMMIT;
GO

