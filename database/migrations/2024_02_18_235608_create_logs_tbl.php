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
            $table->id();
            $table->text('user_id_hash')->nullable();
            $table->text('ip_address');
            $table->text('user_action');
            $table->longText('details');
            $table->text('user_device');
            $table->timestamps();
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
