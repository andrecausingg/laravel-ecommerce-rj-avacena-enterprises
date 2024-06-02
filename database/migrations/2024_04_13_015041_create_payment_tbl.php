<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('payment_tbl', function (Blueprint $table) {
            $table->id();

            $table->text('payment_id')->nullable();

            $table->text('user_id');
            $table->text('purchase_group_id');
            $table->string('voucher_id')->nullable();

            $table->string('payment_method');
            $table->double('total_discounted_amount', 30, 2)->default(0.00);
            $table->double('total_amount', 30, 2)->default(0.00);
            $table->double('money', 30, 2)->default(0.00);
            $table->double('change', 30, 2)->default(0.00);
            $table->string('status')->default('NOT PAID');

            // Date | Time
            $table->timestamp('paid_at')->nullable();
            $table->timestamps();
            $table->softDeletes();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('payment_tbl');
    }
};
