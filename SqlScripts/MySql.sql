START TRANSACTION;

ALTER DATABASE CHARACTER SET utf8mb4;

CREATE TABLE `SigningKeySets` (
    `KeySetId` varchar(95) CHARACTER SET utf8mb4 NOT NULL,
    `Timestamp` datetime(6) NOT NULL,
    CONSTRAINT `PK_SigningKeySets` PRIMARY KEY (`KeySetId`)
) CHARACTER SET=utf8mb4;

CREATE TABLE `SigningKeys` (
    `KeyId` varchar(95) CHARACTER SET utf8mb4 NOT NULL,
    `KetSetId` varchar(95) CHARACTER SET utf8mb4 NULL,
    `ActiveFrom` datetime(6) NOT NULL,
    `ActiveTo` datetime(6) NOT NULL,
    `KeyMaterial` longtext CHARACTER SET utf8mb4 NOT NULL,
    CONSTRAINT `PK_SigningKeys` PRIMARY KEY (`KeyId`),
    CONSTRAINT `FK_SigningKeys_SigningKeySets_KetSetId` FOREIGN KEY (`KetSetId`) REFERENCES `SigningKeySets` (`KeySetId`)
) CHARACTER SET=utf8mb4;

CREATE INDEX `IX_SigningKeys_KetSetId` ON `SigningKeys` (`KetSetId`);

COMMIT;

