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
        Schema::create('users_info_tbl', function (Blueprint $table) {
            $table->id();
            $table->string('user_id_hash');

            // Personal Information
            $table->string('first_name')->nullable();
            $table->string('middle_name')->nullable();
            $table->string('last_name')->nullable();

            // $table->string('suffix')->nullable();
            // $table->string('gender')->nullable();
            // $table->string('birth_date')->nullable();    

            // Contacts
            $table->string('contact_number')->nullable();
            $table->string('email')->nullable();

            // Address
            $table->text('address_1')->nullable();
            $table->text('address_2')->nullable();
            $table->string('region_code')->nullable();  
            $table->string('province_code')->nullable();
            $table->string('city_or_municipality_code')->nullable();
            $table->text('region_name')->nullable();
            $table->text('province_name')->nullable();
            $table->text('city_or_municipality_name')->nullable();
            $table->text('barangay')->nullable();
            $table->text('description_location')->nullable();

            // Date | Time
            $table->timestamp('deleted_at')->nullable();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('users_info_tbl');
    }
};
