/*
  Warnings:

  - A unique constraint covering the columns `[user_id,category_id,month_year]` on the table `budgets` will be added. If there are existing duplicate values, this will fail.

*/
-- AlterTable
ALTER TABLE "transactions" ADD COLUMN     "saving_goal_id" TEXT;

-- CreateIndex
CREATE UNIQUE INDEX "budgets_user_id_category_id_month_year_key" ON "budgets"("user_id", "category_id", "month_year");

-- CreateIndex
CREATE INDEX "transactions_saving_goal_id_idx" ON "transactions"("saving_goal_id");

-- AddForeignKey
ALTER TABLE "transactions" ADD CONSTRAINT "transactions_saving_goal_id_fkey" FOREIGN KEY ("saving_goal_id") REFERENCES "saving_goals"("id") ON DELETE SET NULL ON UPDATE CASCADE;
