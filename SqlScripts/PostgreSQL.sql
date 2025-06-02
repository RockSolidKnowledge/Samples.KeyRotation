START TRANSACTION;

CREATE TABLE "SigningKeySets" (
    "KeySetId" text NOT NULL,
    "Timestamp" timestamp with time zone NOT NULL,
    CONSTRAINT "PK_SigningKeySets" PRIMARY KEY ("KeySetId")
);

CREATE TABLE "SigningKeys" (
    "KeyId" text NOT NULL,
    "KetSetId" text,
    "ActiveFrom" timestamp with time zone NOT NULL,
    "ActiveTo" timestamp with time zone NOT NULL,
    "KeyMaterial" text NOT NULL,
    CONSTRAINT "PK_SigningKeys" PRIMARY KEY ("KeyId"),
    CONSTRAINT "FK_SigningKeys_SigningKeySets_KetSetId" FOREIGN KEY ("KetSetId") REFERENCES "SigningKeySets" ("KeySetId")
);

CREATE INDEX "IX_SigningKeys_KetSetId" ON "SigningKeys" ("KetSetId");

COMMIT;

