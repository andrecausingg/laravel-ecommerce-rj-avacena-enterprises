<?php

namespace Database\Seeders;

use App\Helper\Helper;
use App\Models\AuthModel;
use Faker\Factory as Faker;
use Illuminate\Support\Str;
use App\Models\InventoryModel;
use Illuminate\Support\Carbon;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\DB;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Hash;
use App\Models\InventoryProductModel;
use Illuminate\Support\Facades\Crypt;

class DatabaseSeeder extends Seeder
{
    protected $helper, $fillable_attr_auths, $fillable_attr_inventorys, $fillable_attr_inventory_children;

    public function __construct(Helper $helper, AuthModel $fillable_attr_auths, InventoryModel $fillable_attr_inventorys, InventoryProductModel $fillable_attr_inventory_children)
    {
        $this->helper = $helper;
        $this->fillable_attr_auths = $fillable_attr_auths;
        $this->fillable_attr_inventorys = $fillable_attr_inventorys;
        $this->fillable_attr_inventory_children = $fillable_attr_inventory_children;
    }

    /**
     * Seed the application's database.
     */
    public function run(): void
    {
        DB::beginTransaction();

        try {
            $this->userTblEmail();
            $this->inventoryParentTbl();
            $this->inventoryChildTbl();

            DB::commit();
        } catch (\Exception $e) {
            DB::rollBack();
            Log::error('Seeder error: ' . $e->getMessage());
        }
    }
    private function userTblEmail()
    {
        info('Starting userTblEmail seeder method');

        try {
            // Generate UUID for user_id
            $user_id = Str::uuid()->toString();

            // Data to insert
            $items = [
                [
                    'user_id' => $user_id,
                    'email' => Crypt::encrypt('superadmin@superadmin.com'), // Encrypt email
                    'password' => Hash::make('superadmin@superadmin.com'),
                    'role' => 'SUPER_ADMIN',
                    'status' => 'ACTIVATE',
                    'verification_number' => $this->helper->faker6DigitNumber(),
                    'verify_email_token' => Str::uuid()->toString(),
                    'verify_email_token_expire_at' => Carbon::now()->addHour(), // Example: token valid for 1 hour
                    'email_verified_at' => Carbon::now(),
                    'created_at' => Carbon::now(),
                    'updated_at' => Carbon::now(),
                ],
                [
                    'user_id' => $user_id,
                    'email' => Crypt::encrypt('admin@admin.com'), // Encrypt email
                    'password' => Hash::make('admin@admin.com'),
                    'role' => 'ADMIN',
                    'status' => 'ACTIVATE',
                    'verification_number' => $this->helper->faker6DigitNumber(),
                    'verify_email_token' => Str::uuid()->toString(),
                    'verify_email_token_expire_at' => Carbon::now()->addHour(), // Example: token valid for 1 hour
                    'email_verified_at' => Carbon::now(),
                    'created_at' => Carbon::now(),
                    'updated_at' => Carbon::now(),
                ],
                [
                    'user_id' => $user_id,
                    'email' => Crypt::encrypt('cashier@cashier.com'), // Encrypt email
                    'password' => Hash::make('cashier@cashier.com'),
                    'role' => 'CASHIER',
                    'status' => 'ACTIVATE',
                    'verification_number' => $this->helper->faker6DigitNumber(),
                    'verify_email_token' => Str::uuid()->toString(),
                    'verify_email_token_expire_at' => Carbon::now()->addHour(), // Example: token valid for 1 hour
                    'email_verified_at' => Carbon::now(),
                    'created_at' => Carbon::now(),
                    'updated_at' => Carbon::now(),
                ],
            ];

            // Create the AuthModel instances with the selected attributes
            foreach ($items as $item) {
                $created = AuthModel::create($item);
                if (!$created) {
                    throw new \Exception('Failed to store');
                }

                $expiration_time = Carbon::now()->addHour();
                $token = JWTAuth::claims(['exp' => $expiration_time->timestamp])->fromUser($created);

                $created->update(['verify_email_token' => $token]);
            }
        } catch (\Exception $e) {
            Log::error('Error creating AuthModel: ' . $e->getMessage());
            throw $e; // Re-throw the exception to bubble up to the run() method
        }

        info('Finished userTblEmail seeder method');
    }
    private function inventoryParentTbl()
    {
        info('Starting inventoryParentTbl seeder method');
        // Data to insert
        $items = [
            [
                'name' => "Acrylon",
                'category' => "Paint",
            ],
            [
                'name' => "Aluminum Ladder",
                'category' => "Tools",
            ],
        ];

        foreach ($items as $item) {
            // Prepare data for insertion
            $result_to_create = $this->helper->arrStoreMultipleData($this->fillable_attr_inventorys->arrToStores(), $item);

            // Create the InventoryModel instance with the selected attributes
            $created = InventoryModel::create($result_to_create);
            if (!$created) {
                $error_message = [
                    'message' => 'Failed to store inventory Parent',
                    'parameter' => $created,
                ];
                throw new \Exception(json_encode($error_message));
            }

            $this->helper->updateUniqueId($created, $this->fillable_attr_inventorys->idToUpdate(), $created->id);
        }

        info('Finished inventoryParentTbl seeder method');
    }

    private function inventoryChildTbl()
    {
        info('Starting inventoryChildTbl seeder method');
        $arr_to_store = [
            'inventory_id',
            'item_code',
            'image',
            'name',
            'category',
            'refundable',
            'supplier_name',
            'retail_price',
            'discounted_price',
            'unit_supplier_price',
            'stocks',
        ];

        $inventory1 = InventoryModel::find(1);
        $inventory2 = InventoryModel::find(2);

        $inventory1Enc = Crypt::encrypt($inventory1->inventory_id);
        $inventory2Enc = Crypt::encrypt($inventory2->inventory_id);

        // Data to insert
        $items = [
            [
                'inventory_id' => $inventory1Enc,
                'item_code' => $this->helper->faker12DigitNumber(),
                'image' => null,
                'name' => '2B ACRYLON 4',
                'category' => $inventory1->category, // Assign category from inventory model
                'refundable' => 'yes',
                'supplier_name' => $this->helper->fakerName(),
                'retail_price' => 10.00,
                'discounted_price' => 0.00,
                'unit_supplier_price' => 100.00,
                'stocks' => 100,
            ],
            [
                'inventory_id' => $inventory1Enc,
                'item_code' => $this->helper->faker12DigitNumber(),
                'name' => '2B ACRYLON 7',
                'category' => $inventory1->category,
                'refundable' => 'yes',
                'supplier_name' => $this->helper->fakerName(),
                'retail_price' => 100.00,
                'discounted_price' => 50.00,
                'unit_supplier_price' => 200.00,
                'stocks' => 100,
            ],
            [
                'inventory_id' => $inventory1Enc,
                'item_code' => $this->helper->faker12DigitNumber(),
                'name' => '2B ACRYLON 9',
                'category' => $inventory1->category,
                'refundable' => 'no',
                'supplier_name' => $this->helper->fakerName(),
                'retail_price' => 100.00,
                'discounted_price' => 0.00,
                'unit_supplier_price' => 500.00,
                'stocks' => 100,
            ],
            [
                'inventory_id' => $inventory2Enc,
                'item_code' => $this->helper->faker12DigitNumber(),
                'name' => '2B ALUMINUM LADDER 12 STEP',
                'category' => $inventory2->category,
                'refundable' => 'yes',
                'supplier_name' => $this->helper->fakerName(),
                'retail_price' => 100.00,
                'discounted_price' => 50.00,
                'unit_supplier_price' => 200.00,
                'stocks' => 100,
            ],
            [
                'inventory_id' => $inventory2Enc,
                'item_code' => $this->helper->faker12DigitNumber(),
                'name' => '2B ALUMINUM LADDER 10 STEP',
                'category' => $inventory2->category,
                'refundable' => 'no',
                'supplier_name' => $this->helper->fakerName(),
                'retail_price' => 100.00,
                'discounted_price' => 0.00,
                'unit_supplier_price' => 500.00,
                'stocks' => 100,
            ],
            [
                'inventory_id' => $inventory2Enc, // Corrected inventory_id to inventoryId2
                'item_code' => $this->helper->faker12DigitNumber(),
                'name' => '2B ALUMINUM LADDER 9 STEP',
                'category' => $inventory2->category,
                'refundable' => 'no',
                'supplier_name' => $this->helper->fakerName(),
                'retail_price' => 100.00,
                'discounted_price' => 0.00,
                'unit_supplier_price' => 500.00,
                'stocks' => 100,
            ],
        ];

        foreach ($items as $item) {

            // Prepare data for insertion
            $result_to_create = $this->helper->arrStoreMultipleData($arr_to_store, $item);
            info($result_to_create);

            // Create the InventoryProductModel instance with the selected attributes
            $created = InventoryProductModel::create($result_to_create);

            if (!$created) {
                $error_message = [
                    'message' => 'Failed to store inventory Parent',
                    'parameter' => $created,
                ];
                throw new \Exception(json_encode($error_message));
            }

            $this->helper->updateUniqueId($created, $this->fillable_attr_inventory_children->idToUpdate(), $created->id);
        }

        info('Finished inventoryChildTbl seeder method');
    }
}
