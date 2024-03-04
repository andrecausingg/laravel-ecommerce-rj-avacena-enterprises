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
            $table->longText('image')->nullable();

            // Personal Information
            $table->longText('first_name');
            $table->longText('middle_name')->nullable();
            $table->longText('last_name');

            // $table->string('suffix')->nullable();
            // $table->string('gender')->nullable();
            // $table->string('birth_date')->nullable();    

            // Contacts
            $table->string('contact_number')->nullable();
            $table->string('email')->nullable();

            // Address
            $table->longText('address_1');
            $table->longText('address_2')->nullable();
            $table->longText('region_code');  
            $table->longText('province_code');
            $table->longText('city_or_municipality_code');
            $table->longText('region_name');
            $table->longText('province_name');
            $table->longText('city_or_municipality_name');
            $table->longText('barangay');
            $table->longText('description_location')->nullable();

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
        Schema::dropIfExists('users_info_tbl');
    }
};
