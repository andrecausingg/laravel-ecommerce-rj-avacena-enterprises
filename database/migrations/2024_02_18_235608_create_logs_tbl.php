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
        Schema::create('logs_tbl', function (Blueprint $table) {
            // Ids
            $table->id();
            $table->text('log_id')->unique()->nullable();
            $table->text('user_id')->nullable();
            
            // 
            $table->tinyInteger('is_sensitive')->default(0);
            $table->text('ip_address');
            $table->text('user_action');
            $table->longText('details');
            $table->text('user_device');

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
        Schema::dropIfExists('logs_tbl');
    }
};
