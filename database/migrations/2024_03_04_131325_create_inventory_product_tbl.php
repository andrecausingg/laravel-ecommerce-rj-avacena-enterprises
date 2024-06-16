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
        Schema::create('inventory_product_tbl', function (Blueprint $table) {
            // Ids
            $table->id();

            $table->text('inventory_product_id')->nullable();
            $table->text('inventory_id');

            // Name 
            $table->string('item_code');
            $table->longText('image')->nullable();
            $table->text('name');
            $table->string('category')->nullable();
            $table->longText('description')->nullable();
            $table->string('refundable');
            $table->text('supplier_name')->nullable();
            $table->text('design')->nullable();
            $table->string('size')->nullable();
            $table->string('color')->nullable();

            // Prices
            $table->double('retail_price', 30, 2)->default(0.00);
            $table->double('discounted_price', 30, 2)->default(0.00);
            $table->double('unit_supplier_price', 30, 2)->default(0.00);

            // Stock
            $table->bigInteger('stocks')->default(0);

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
        Schema::dropIfExists('inventory_product_tbl');
    }
};
