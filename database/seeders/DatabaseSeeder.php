<?php

namespace Database\Seeders;

// use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\DB;

class DatabaseSeeder extends Seeder
{
    /**
     * Seed the application's database.
     */
    public function run(): void
    {
        // \App\Models\User::factory(10)->create();

        // \App\Models\User::factory()->create([
        //     'name' => 'Test User',
        //     'email' => 'test@example.com',
        // ]);


        DB::table('personal_access_tokens')->insert([
            [
                'tokenable_type' => 'App\Models\User',
                'tokenable_id' => 1,
                'name' => 'API Token',
                'token' => hash('sha256', 'Xly8kvgcWxFpaQm1gXh1O4PuD7N78xuD'),
                'abilities' => json_encode(['*']),
                'last_used_at' => '2023-06-01 12:34:56',
                'expires_at' => '2023-12-01 12:34:56',
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'tokenable_type' => 'App\Models\User',
                'tokenable_id' => 2,
                'name' => 'Mobile App Token',
                'token' => hash('sha256', 'hglB3xQvhzmZ9qxycNfp8gkS5WuZDxGJ'),
                'abilities' => json_encode(['read', 'write']),
                'last_used_at' => '2023-06-02 12:34:56',
                'expires_at' => '2023-12-02 12:34:56',
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'tokenable_type' => 'App\Models\User',
                'tokenable_id' => 1,
                'name' => 'Web Token',
                'token' => hash('sha256', 'Knd2L5tzL3vsXqBm8Qj7pZkS9VcW1hGJ'),
                'abilities' => json_encode(['read']),
                'last_used_at' => '2023-06-03 12:34:56',
                'expires_at' => '2023-12-03 12:34:56',
                'created_at' => now(),
                'updated_at' => now(),
            ],
        ]);
    }
}
