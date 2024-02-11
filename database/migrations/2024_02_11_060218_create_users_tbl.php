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
        Schema::create('users_tbl', function (Blueprint $table) {
            $table->id();
            $table->text('id_hash')->unique();
            $table->text('phone_number')->unique()->nullable();
            $table->text('email')->unique()->nullable();
            $table->text('password');
            $table->string('role');
            $table->string('status');
            $table->integer('verification_number');
            $table->string('verification_key')->nullable();
            $table->timestamp('phone_verified_at')->nullable();
            $table->timestamp('email_verified_at')->nullable();
            $table->timestamp('update_password_at')->nullable();
            $table->timestamp('deleted_at')->nullable();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('users_tbl');
    }
};
