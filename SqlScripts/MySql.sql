START TRANSACTION;

CREATE TABLE `RskSecurityKeySets` (
    `KeySetId` varchar(255) NOT NULL,
    `ConcurrencyTimestamp` datetime(6) NOT NULL,
     PRIMARY KEY (`KeySetId`)
);

CREATE TABLE `RskSecurityKeys` (
    `KeyId` varchar(255) NOT NULL,
    `KeySetId` varchar(255) NULL,
    `ActiveFrom` datetime NOT NULL,
    `ActiveTo` datetime NOT NULL,
    `KeyMaterial` longtext NOT NULL,
     PRIMARY KEY (`KeyId`),
     CONSTRAINT `FK_RskSecurityKeys_RskSecurityKeySets_KeySetId` FOREIGN KEY (`KeySetId`) REFERENCES `RskSecurityKeySets` (`KeySetId`)
);

CREATE INDEX `IX_RskSecurityKeys_KeySetId` ON `RskSecurityKeys` (`KeySetId`);

COMMIT;

