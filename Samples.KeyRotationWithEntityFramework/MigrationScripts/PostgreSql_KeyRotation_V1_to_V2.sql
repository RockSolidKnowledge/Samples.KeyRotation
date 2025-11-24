START TRANSACTION;

ALTER TABLE "SigningKeys" DROP CONSTRAINT "FK_SigningKeys_SigningKeySets_KetSetId";

ALTER TABLE "SigningKeySets" DROP CONSTRAINT "PK_SigningKeySets";

ALTER TABLE "SigningKeys" DROP CONSTRAINT "PK_SigningKeys";

ALTER TABLE "SigningKeys" RENAME TO "RskSecurityKeys";

ALTER TABLE "RskSecurityKeys" RENAME COLUMN "KetSetId" TO "KeySetId";

ALTER TABLE "SigningKeySets" RENAME TO "RskSecurityKeySets";

UPDATE "RskSecurityKeys" SET "KeySetId" = 'Product.KeyRotation.OpenIddict.SigningKeySet'
WHERE "KeySetId" = 'Product.KeyRotation.OpenIddict.KeySet';

UPDATE "RskSecurityKeySets" SET "KeySetId" = 'Product.KeyRotation.OpenIddict.SigningKeySet'
WHERE "KeySetId" = 'Product.KeyRotation.OpenIddict.KeySet';

UPDATE "RskSecurityKeys"
SET "KeyId" = 'Product.KeyRotation.OpenIddict.SigningKeySet.' || "KeyId"
WHERE "KeySetId" = 'Product.KeyRotation.OpenIddict.SigningKeySet';

ALTER TABLE "RskSecurityKeySets" ADD CONSTRAINT "PK_RskSecurityKeySets" PRIMARY KEY ("KeySetId");

ALTER TABLE "RskSecurityKeys" ADD CONSTRAINT "PK_RskSecurityKeys" PRIMARY KEY ("KeyId");

ALTER TABLE "RskSecurityKeys" ADD CONSTRAINT "FK_RskSecurityKeys_RskSecurityKeySets_KeySetId" FOREIGN KEY ("KeySetId") REFERENCES "RskSecurityKeySets" ("KeySetId");

INSERT INTO "__EFMigrationsHistory" ("MigrationId", "ProductVersion")
VALUES ('20251128152819_KeyRotation_V2', '8.0.22');

COMMIT;

