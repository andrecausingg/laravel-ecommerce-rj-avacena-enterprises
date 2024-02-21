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
            $table->text('user_id_hash');
            
            // Profile Picture
            $table->text('image')->nullable();

            // Personal Information
            $table->text('first_name');
            $table->text('middle_name')->nullable();
            $table->text('last_name');

            // $table->string('suffix')->nullable();
            // $table->string('gender')->nullable();
            // $table->string('birth_date')->nullable();    

            // Contacts
            $table->string('contact_number')->nullable();
            $table->string('email')->nullable();

            // Address
            $table->text('address_1');
            $table->text('address_2')->nullable();
            $table->text('region_code');  
            $table->text('province_code');
            $table->text('city_or_municipality_code');
            $table->text('region_name');
            $table->text('province_name');
            $table->text('city_or_municipality_name');
            $table->text('barangay');
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
