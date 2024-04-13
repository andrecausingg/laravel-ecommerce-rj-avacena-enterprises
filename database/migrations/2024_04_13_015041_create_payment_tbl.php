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

            $table->text('payment_id')->unique()->nullable();

            $table->text('user_id')->nullable();
            $table->text('purchase_group_id');

            $table->string('payment_method');
            $table->double('discount_amount', 30, 2);
            $table->double('amount', 30, 2);

            // Date | Time
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
