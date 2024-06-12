<?php

namespace Database\Seeders;

// use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Faker\Factory as Faker;
use Illuminate\Support\Str;
use Illuminate\Support\Carbon;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Crypt;

class DatabaseSeeder extends Seeder
{
    /**
     * Seed the application's database.
     */
    public function run(): void
    {
        $faker = Faker::create();

        for ($i = 0; $i < 3; $i++) {
            DB::table('users_tbl')->insert([
                'user_id' => Str::uuid()->toString(),
                'phone_number' => null,
                'email' => Crypt::encrypt($faker->unique()->safeEmail),
                'password' => Hash::make('password'), // Change 'password' to the actual password if needed
                'role' => 'CLIENT',
                'status' => 'ACTIVATE',
                'verification_number' => $faker->numberBetween(100000, 999999),
                'verification_key' => null,
                'session_token' => null,
                'verify_email_token' => Str::random(60),
                'verify_phone_token' => null,
                'reset_password_token' => null,
                'session_expire_at' => null,
                'verify_email_token_expire_at' => Carbon::now()->addDays(1),
                'verify_token_expire_at' => null,
                'reset_password_token_expire_at' => null,
                'phone_verified_at' => null,
                'email_verified_at' => Carbon::now(),
                'update_password_at' => null,
                'created_at' => Carbon::now(),
                'updated_at' => Carbon::now(),
                'deleted_at' => null,
            ]);
        }

        // \App\Models\User::factory(10)->create();

        // \App\Models\User::factory()->create([
        //     'name' => 'Test User',
        //     'email' => 'test@example.com',
        // ]);

        // DB::table('personal_access_tokens')->insert([
        //     [
        //         'tokenable_type' => 'App\Models\User',
        //         'tokenable_id' => 1,
        //         'name' => 'API Token',
        //         'token' => hash('sha256', 'Xly8kvgcWxFpaQm1gXh1O4PuD7N78xuD'),
        //         'abilities' => json_encode(['*']),
        //         'last_used_at' => '2023-06-01 12:34:56',
        //         'expires_at' => '2023-12-01 12:34:56',
        //         'created_at' => now(),
        //         'updated_at' => now(),
        //     ],
        //     [
        //         'tokenable_type' => 'App\Models\User',
        //         'tokenable_id' => 2,
        //         'name' => 'Mobile App Token',
        //         'token' => hash('sha256', 'hglB3xQvhzmZ9qxycNfp8gkS5WuZDxGJ'),
        //         'abilities' => json_encode(['read', 'write']),
        //         'last_used_at' => '2023-06-02 12:34:56',
        //         'expires_at' => '2023-12-02 12:34:56',
        //         'created_at' => now(),
        //         'updated_at' => now(),
        //     ],
        //     [
        //         'tokenable_type' => 'App\Models\User',
        //         'tokenable_id' => 1,
        //         'name' => 'Web Token',
        //         'token' => hash('sha256', 'Knd2L5tzL3vsXqBm8Qj7pZkS9VcW1hGJ'),
        //         'abilities' => json_encode(['read']),
        //         'last_used_at' => '2023-06-03 12:34:56',
        //         'expires_at' => '2023-12-03 12:34:56',
        //         'created_at' => now(),
        //         'updated_at' => now(),
        //     ],
        // ]);
    }
}
