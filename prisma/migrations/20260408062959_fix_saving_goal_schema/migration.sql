-- DropIndex
DROP INDEX "transactions_user_id_idx";

-- AlterTable
ALTER TABLE "saving_goals" ADD COLUMN     "is_round_up" BOOLEAN NOT NULL DEFAULT false;

-- CreateIndex
CREATE INDEX "transactions_user_id_date_idx" ON "transactions"("user_id", "date");

-- CreateIndex
CREATE INDEX "transactions_user_id_type_date_idx" ON "transactions"("user_id", "type", "date");
