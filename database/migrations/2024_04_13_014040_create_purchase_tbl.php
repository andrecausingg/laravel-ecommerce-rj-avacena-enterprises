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
        Schema::create('purchase_tbl', function (Blueprint $table) {
            $table->id();

            $table->text('purchase_id')->unique()->nullable();
            $table->text('purchase_group_id');

            $table->text('user_id')->nullable();
            $table->text('inventory_product_id');

            $table->status('status');

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
        Schema::dropIfExists('purchase_tbl');
    }
};
