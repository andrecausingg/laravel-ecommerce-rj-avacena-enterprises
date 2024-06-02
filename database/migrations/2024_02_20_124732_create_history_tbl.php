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
        Schema::create('history_tbl', function (Blueprint $table) {
            // Ids
            $table->id();
            $table->text('history_id')->nullable();

            // 
            $table->text('tbl_id');
            $table->string('tbl_name');
            $table->string('column_name');
            $table->longText('value');

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
        Schema::dropIfExists('history_tbl');
    }
};
