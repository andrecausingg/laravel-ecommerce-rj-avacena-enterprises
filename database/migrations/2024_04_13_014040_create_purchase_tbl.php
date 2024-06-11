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

            // This Table I.Ds
            $table->text('purchase_id')->nullable();
            $table->text('purchase_group_id')->nullable();

            // User I.Ds
            $table->text('user_id_customer')->nullable();
            $table->text('user_id_ecom')->nullable();
            $table->text('user_id_menu')->nullable();

            // Inventory I.Ds
            $table->text('inventory_id');
            $table->text('inventory_product_id');
            $table->string('item_code');

            // Name 
            $table->longText('image')->nullable();
            $table->text('name');
            $table->string('category')->nullable();
            $table->longText('description')->nullable();
            $table->text('supplier_name')->nullable();
            $table->text('design')->nullable();
            $table->string('size')->nullable();
            $table->string('color')->nullable();

            // Prices
            $table->double('retail_price', 30, 2)->default(0.00);
            $table->double('discounted_price', 30, 2)->default(0.00);
            $table->double('unit_supplier_price', 30, 2)->default(0.00);

            // Status
            $table->string('status')->default('NOT PAID')->comment('NOT PAID | VOID | DONE');

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
