START TRANSACTION;

CREATE TABLE "RskSecurityKeySets"
(
    "KeySetId"             text NOT NULL,
    "ConcurrencyTimestamp" timestamp with time zone NOT NULL,
    CONSTRAINT "PK_RskSecurityKeySets" PRIMARY KEY ("KeySetId")
);

CREATE TABLE "RskSecurityKeys"
(
    "KeyId"      text NOT NULL,
    "KeySetId"   text,
    "ActiveFrom" timestamp with time zone NOT NULL,
    "ActiveTo" timestamp with time zone NOT NULL,
    "KeyMaterial" text NOT NULL,
    CONSTRAINT "PK_RskSecurityKeys" PRIMARY KEY ("KeyId"),
    CONSTRAINT "FK_RskSecurityKeys_RskSecurityKeySets_KeySetId" FOREIGN KEY ("KeySetId") REFERENCES "RskSecurityKeySets" ("KeySetId")
);

CREATE INDEX "IX_RskSecurityKeys_KeySetId" ON "RskSecurityKeys" ("KeySetId");

COMMIT;

