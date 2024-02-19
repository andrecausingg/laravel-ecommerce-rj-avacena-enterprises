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
            $table->string('user_id_hash');
            $table->string('ip_address');
            $table->string('user_action');
            $table->string('details');
            $table->string('user_device');
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
