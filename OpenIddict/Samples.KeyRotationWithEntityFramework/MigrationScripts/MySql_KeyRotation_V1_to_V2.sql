START TRANSACTION;

ALTER TABLE `SigningKeys` DROP CONSTRAINT `FK_SigningKeys_SigningKeySets_KetSetId`;

ALTER TABLE SigningKeys RENAME RskSecurityKeys;

ALTER TABLE `RskSecurityKeys` CHANGE `KetSetId` `KeySetId` varchar(255) NULL;

ALTER TABLE SigningKeySets RENAME RskSecurityKeySets;

UPDATE `RskSecurityKeys` SET `KeySetId` = 'Product.KeyRotation.OpenIddict.SigningKeySet'
WHERE `KeySetId` = 'Product.KeyRotation.OpenIddict.KeySet';
SELECT ROW_COUNT();


UPDATE `RskSecurityKeySets` SET `KeySetId` = 'Product.KeyRotation.OpenIddict.SigningKeySet'
WHERE `KeySetId` = 'Product.KeyRotation.OpenIddict.KeySet';
SELECT ROW_COUNT();


  UPDATE `RskSecurityKeys`
  SET KeyId = CONCAT('Product.KeyRotation.OpenIddict.SigningKeySet.', KeyId)
  WHERE KeySetId = 'Product.KeyRotation.OpenIddict.SigningKeySet';

ALTER TABLE `RskSecurityKeys` ADD CONSTRAINT `FK_RskSecurityKeys_RskSecurityKeySets_KeySetId` FOREIGN KEY (`KeySetId`) REFERENCES `RskSecurityKeySets` (`KeySetId`);

INSERT INTO `__EFMigrationsHistory` (`MigrationId`, `ProductVersion`)
VALUES ('20251128150802_KeyRotation_V2', '8.0.22');

COMMIT;

