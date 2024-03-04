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
        Schema::create('inventory_items_tbl', function (Blueprint $table) {
            $table->id();
            $table->text('inventory_group_product_id');
            $table->text('product_id');
            $table->string('item_code');

            // Default 
            $table->longText('image')->nullable();
            $table->text('name');
            $table->longText('description')->nullable();
            $table->string('is_refund')->default('no');
            $table->string('category')->nullable();

            // Original Price
            $table->string('retail_price')->nullable();
            $table->double('discounted_price', 30, 2)->default(0.00);
            $table->bigInteger('stock')->default(0);

            // Supplier
            $table->text('supplier_name')->nullable();
            $table->double('unit_supplier_price', 30, 2)->default(0.00);

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
        Schema::dropIfExists('inventory_items_tbl');
    }
};
