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
            // Ids
            $table->id();
            $table->uuid('user_id'); // Changed to uuid

            // Authentication
            $table->longText('phone_number')->unique()->nullable();
            $table->longText('email')->unique()->nullable();
            $table->longText('password');
            $table->string('role');
            $table->string('status');

            // Verifications
            $table->integer('verification_number')->nullable();
            $table->longText('verification_key')->nullable();

            // Token
            $table->longText('session_token')->nullable();
            $table->longText('verify_email_token')->nullable();
            $table->longText('verify_phone_token')->nullable();
            $table->longText('reset_password_token')->nullable();

            // Expire Time
            $table->timestamp('session_expire_at')->nullable();
            $table->timestamp('verify_email_token_expire_at')->nullable();
            $table->timestamp('verify_phone_token_expire_at')->nullable();
            $table->timestamp('reset_password_token_expire_at')->nullable();

            // Verified At
            $table->timestamp('phone_verified_at')->nullable();
            $table->timestamp('email_verified_at')->nullable();
            $table->timestamp('update_password_at')->nullable();

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
        Schema::dropIfExists('users_tbl');
    }
};
