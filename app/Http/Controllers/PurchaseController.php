<?php

namespace App\Http\Controllers;

use App\Models\PaymentModel;
use Illuminate\Http\Request;
use App\Models\PurchaseModel;
use Illuminate\Support\Facades\DB;
use App\Models\InventoryProductModel;
use Illuminate\Support\Facades\Crypt;
use App\Helper\Helper;
use Illuminate\Support\Facades\Validator;
use Symfony\Component\HttpFoundation\Response;

class PurchaseController extends Controller
{

    protected $helper, $fillable_attr_purchase, $fillable_attr_inventory_product, $fillable_attr_payment;

    public function __construct(Helper $helper, PurchaseModel $fillable_attr_purchase, InventoryProductModel $fillable_attr_inventory_product, PaymentModel $fillable_attr_payment)
    {
        $this->helper = $helper;
        $this->fillable_attr_purchase = $fillable_attr_purchase;
        $this->fillable_attr_inventory_product = $fillable_attr_inventory_product;
        $this->fillable_attr_payment = $fillable_attr_payment;
    }

    public function store(Request $request)
    {
        $status = 'NOT PAID';
        $ctr = 0;
        $arr_store_fresh_create = [];
        $arr_all_purchase = [];

        // Authorize the user
        $user = $this->helper->authorizeUser($request);
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        // Validation rules for each item in the array
        $validator = Validator::make($request->all(), [
            'inventory_product_id' => 'required|string',
            'purchase_group_id' => 'nullable',
            'user_id_customer' => 'nullable',
            'quantity' => 'required|numeric|min:1',
            'eu_device' => 'required|string',
        ]);

        // Check if validation fails
        if ($validator->fails()) {
            return response()->json(
                [
                    'message' => $validator->errors(),
                ],
                Response::HTTP_UNPROCESSABLE_ENTITY
            );
        }

        // Validate Eu Device
        $result_validate_eu_device = $this->helper->validateEuDevice($request->eu_device);
        if ($result_validate_eu_device) {
            return $result_validate_eu_device;
        }

        // Start the transaction
        DB::beginTransaction();

        try {
            // Decrypted Variables
            $decrypted_inventory_product_id = $request->inventory_product_id != "" && $request->inventory_product_id != null ? Crypt::decrypt($request->inventory_product_id) : null;
            $decrypted_purchase_group_id = isset($request->purchase_group_id) &&  $request->purchase_group_id != "" && $request->purchase_group_id != null ? Crypt::decrypt($request->purchase_group_id) : null;
            $decrypted_purchase_user_id_customer = isset($request->user_id_customer) &&  $request->user_id_customer != "" && $request->user_id_customer != null ? Crypt::decrypt($request->user_id_customer) : null;

            $inventory_product = InventoryProductModel::where('inventory_product_id', $decrypted_inventory_product_id)->first();
            if (!$inventory_product) {
                return response()->json(['message' => 'Inventory Product ID not found'], Response::HTTP_NOT_FOUND);
            }

            if ($inventory_product->stocks < $request->quantity) {
                return response()->json(['message' => 'Sorry, can\'t add due to insufficient stock', 'stocks' => $inventory_product->stocks], Response::HTTP_UNPROCESSABLE_ENTITY);
            }

            // Add New Item on purchase_group_id
            if (
                $decrypted_inventory_product_id != '' &&
                $decrypted_purchase_group_id != '' && $decrypted_purchase_group_id != null &&  $decrypted_purchase_group_id != false &&
                $decrypted_purchase_user_id_customer != '' && $decrypted_purchase_user_id_customer != null &&  $decrypted_purchase_user_id_customer != false
            ) {
                do {
                    foreach ($this->fillable_attr_purchase->arrToStores() as $arrToStores) {
                        if ($arrToStores == 'purchase_group_id') {
                            $arr_store_fresh_create[$arrToStores] = $decrypted_purchase_group_id;
                        } else if ($arrToStores == 'user_id_customer') {
                            $arr_store_fresh_create[$arrToStores] = $decrypted_purchase_user_id_customer;
                        } else if ($arrToStores == 'inventory_product_id') {
                            $arr_store_fresh_create[$arrToStores] =  $decrypted_inventory_product_id;
                        } else if ($arrToStores == 'user_id_menu') {
                            $arr_store_fresh_create[$arrToStores] = $user->user_id;
                        } else if ($arrToStores == 'status') {
                            $arr_store_fresh_create[$arrToStores] = $status;
                        } else {
                            $arr_store_fresh_create[$arrToStores] = $inventory_product->$arrToStores;
                        }
                    }

                    // Create a new purchase record
                    $created_purchase = PurchaseModel::create($arr_store_fresh_create);
                    if (!$created_purchase) {
                        DB::rollBack();
                        return response()->json(
                            ['message' => 'Failed to store purchase'],
                            Response::HTTP_INTERNAL_SERVER_ERROR
                        );
                    }

                    // Update the unique I.D
                    $update_unique_id = $this->helper->updateUniqueId($created_purchase, $this->fillable_attr_purchase->idToUpdatePurchase(), $created_purchase->id);
                    if ($update_unique_id) {
                        DB::rollBack();
                        return $update_unique_id;
                    }

                    // Minus Stock
                    $minus_stock = $this->minusStock($decrypted_inventory_product_id);
                    $total_amount_payment = $this->totalAmountPayment($decrypted_purchase_group_id, $created_purchase->user_id_customer);

                    // Update the payment record
                    $payment = PaymentModel::where('purchase_group_id', $created_purchase->purchase_group_id)->first();

                    if (!$payment) {
                        DB::rollBack();
                        return response()->json(
                            ['message' => 'Payment record not found'],
                            Response::HTTP_NOT_FOUND
                        );
                    }

                    $payment->update([
                        'total_amount' => $total_amount_payment['total_amount'],
                        'total_discounted_amount' => $total_amount_payment['total_discounted_amount'],
                    ]);

                    // Re-fetch the updated payment record
                    $updated_payment = PaymentModel::where('id', $payment->id)->first();


                    // Store logs for create Purchase
                    $arr_all_purchase['purchase']['fields'][] = $created_purchase;
                    // Store logs for create Purchase
                    $arr_all_purchase['payment']['fields'][] = $updated_payment;

                    $ctr++;
                } while ($ctr < $request->quantity);

                $arr_log_details[] = $arr_all_purchase;

                // Arr Data Logs
                $arr_data_logs = [
                    'user_device' => $request->eu_device,
                    'user_id' => $user->user_id,
                    'is_sensitive' => 0,
                    'is_history' => 0,
                    'log_details' => $arr_log_details,
                    'user_action' => 'ADDED NEW PURCHASE ITEM',
                ];

                // Logs
                $log_result = $this->helper->log($request, $arr_data_logs);
                if ($log_result->getStatusCode() !== Response::HTTP_OK) {
                    DB::rollBack();
                    return $log_result;
                }

                // Commit the transaction
                DB::commit();

                return response()->json(
                    [
                        'message' => 'Purchase and Payment records stored successfully',
                        'message_stocks' => $minus_stock,
                    ],
                    Response::HTTP_OK
                );
            }
            // Fresh Create
            else {
                $ctr = 0;
                $group_purchase_id = $this->generateGroupPurchaseId();
                $new_customer_id = $this->generateCustomerId();

                if ($group_purchase_id == '') {
                    DB::rollBack();
                    return response()->json(
                        ['message' => 'Failed generate purchase I.D'],
                        Response::HTTP_INTERNAL_SERVER_ERROR
                    );
                }

                if ($new_customer_id == '') {
                    DB::rollBack();
                    return response()->json(
                        ['message' => 'Failed generate costumer I.D'],
                        Response::HTTP_INTERNAL_SERVER_ERROR
                    );
                }

                do {
                    // STEP 1 Fresh Create start 0
                    if ($ctr == 0) {
                        foreach ($this->fillable_attr_purchase->arrToStores() as $arrToStores) {
                            if ($arrToStores == 'user_id_customer') {
                                $arr_store_fresh_create[$arrToStores] = $new_customer_id;
                            } else if ($arrToStores == 'purchase_group_id') {
                                $arr_store_fresh_create[$arrToStores] = $group_purchase_id;
                            } else if ($arrToStores == 'user_id_menu') {
                                $arr_store_fresh_create[$arrToStores] = $user->user_id;
                            } else if ($arrToStores == 'status') {
                                $arr_store_fresh_create[$arrToStores] = $status;
                            } else {
                                $arr_store_fresh_create[$arrToStores] = $inventory_product->$arrToStores;
                            }
                        }

                        // Create a new purchase record
                        $created_purchase = PurchaseModel::create($arr_store_fresh_create);
                        if (!$created_purchase) {
                            DB::rollBack();
                            return response()->json(
                                ['message' => 'Failed to store purchase'],
                                Response::HTTP_INTERNAL_SERVER_ERROR
                            );
                        }

                        // Update the unique I.D Purchase
                        $update_unique_id = $this->helper->updateUniqueId($created_purchase, $this->fillable_attr_purchase->idToUpdatePurchase(), $created_purchase->id);
                        if ($update_unique_id) {
                            DB::rollBack();
                            return $update_unique_id;
                        }

                        // Minus Stock
                        $minus_stock = $this->minusStock($decrypted_inventory_product_id);
                        $total_amount_payment = $this->totalAmountPayment($created_purchase->purchase_group_id, $created_purchase->user_id_customer);

                        // Create a new payment record
                        $created_payment = PaymentModel::create([
                            'user_id' => $created_purchase->user_id_customer,
                            'purchase_group_id' => $created_purchase->purchase_group_id,
                            'payment_method' => 'CASH',
                            'total_amount' => $total_amount_payment['total_amount'],
                            'total_discounted_amount' => $total_amount_payment['total_discounted_amount'],
                            'status' => $status,
                        ]);
                        if (!$created_payment) {
                            DB::rollBack();
                            return response()->json(
                                ['message' => 'Failed to store payment'],
                                Response::HTTP_INTERNAL_SERVER_ERROR
                            );
                        }

                        // Update the unique I.D Payment
                        $update_unique_id = $this->helper->updateUniqueId($created_payment, $this->fillable_attr_purchase->idToUpdatePayment(), $created_payment->id);
                        if ($update_unique_id) {
                            DB::rollBack();
                            return $update_unique_id;
                        }

                        // Store logs for create Purchase
                        $arr_all_purchase['purchase'][] = $created_purchase;
                        // Store logs for create Purchase
                        $arr_all_purchase['payment'][] = $created_payment;
                    }
                    // STEP 2 Fresh Create but greater 0 quantity 
                    else {
                        foreach ($this->fillable_attr_purchase->arrToStores() as $arrToStores) {
                            if ($arrToStores == 'user_id_customer') {
                                $arr_store_fresh_create[$arrToStores] = $new_customer_id;
                            } else if ($arrToStores == 'purchase_group_id') {
                                $arr_store_fresh_create[$arrToStores] = $group_purchase_id;
                            } else if ($arrToStores == 'user_id_menu') {
                                $arr_store_fresh_create[$arrToStores] = $user->user_id;
                            } else if ($arrToStores == 'status') {
                                $arr_store_fresh_create[$arrToStores] = $status;
                            } else {
                                $arr_store_fresh_create[$arrToStores] = $inventory_product->$arrToStores;
                            }
                        }

                        // Create a new purchase record
                        $created_purchase = PurchaseModel::create($arr_store_fresh_create);
                        if (!$created_purchase) {
                            DB::rollBack();
                            return response()->json(
                                ['message' => 'Failed to store purchase'],
                                Response::HTTP_INTERNAL_SERVER_ERROR
                            );
                        }

                        // Update the unique I.D
                        $update_unique_id = $this->helper->updateUniqueId($created_purchase, $this->fillable_attr_purchase->idToUpdatePurchase(), $created_purchase->id);
                        if ($update_unique_id) {
                            DB::rollBack();
                            // Retun only if theres an error
                            return $update_unique_id;
                        }

                        // Minus Stock
                        $minus_stock = $this->minusStock($decrypted_inventory_product_id);
                        $total_amount_payment = $this->totalAmountPayment($created_purchase->purchase_group_id, $created_purchase->user_id_customer);

                        // Update the payment record
                        $payment = PaymentModel::where('purchase_group_id', $created_purchase->purchase_group_id)->first();

                        if (!$payment) {
                            DB::rollBack();
                            return response()->json(
                                ['message' => 'Payment record not found'],
                                Response::HTTP_NOT_FOUND
                            );
                        }

                        $payment->update([
                            'total_amount' => $total_amount_payment['total_amount'],
                            'total_discounted_amount' => $total_amount_payment['total_discounted_amount'],
                        ]);

                        // Re-fetch the updated payment record
                        $updated_payment = PaymentModel::where('id', $payment->id)->first();

                        // Store logs for create Purchase
                        $arr_all_purchase['purchase'][] = $created_purchase;
                        // Store logs for update Payment
                        $arr_all_purchase['payment'][] = $updated_payment;
                    }

                    $ctr++;
                } while ($ctr < $request->quantity);

                $arr_log_details['fields'] = $arr_all_purchase;

                // Arr Data Logs
                $arr_data_logs = [
                    'user_device' => $request->eu_device,
                    'user_id' => $user->user_id,
                    'is_sensitive' => 0,
                    'is_history' => 0,
                    'log_details' => $arr_log_details,
                    'user_action' => 'STORE PURCHASE ITEM',
                ];

                // Logs
                $log_result = $this->helper->log($request, $arr_data_logs);
                if ($log_result->getStatusCode() !== Response::HTTP_OK) {
                    DB::rollBack();
                    return $log_result;
                }

                // Commit the transaction
                DB::commit();

                return response()->json(
                    [
                        'message' => 'Purchase and Payment records stored successfully',
                        // 'message_stocks' => $minus_stock,
                    ],
                    Response::HTTP_OK
                );
            }
        } catch (\Exception $e) {
            DB::rollBack();
            return response()->json(['message' => $e->getMessage()], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    // public function updateQty(Request $request)
    // {
    //     // Authorize the user
    //     $user = $this->helper->authorizeUser($request);
    //     if (empty($user->user_id)) {
    //         return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
    //     }

    //     if ($request->input('operator') == 'increment') {
    //         // Call addQty method
    //         return $this->addQty($request);
    //     } else if ($request->input('operator')  == 'decrement') {
    //         // Call minusQty method
    //         return $this->minusQty($request);
    //     } else {
    //         return response()->json(['message' => 'Invalid operation. Specify increment or decrement.'], Response::HTTP_BAD_REQUEST);
    //     }
    // }


    public function updateQty(Request $request)
    {
        $arr_add_purchase = [];
        $arr_minus_purchase = [];
        $ctr = 0;
        $qty = 0;

        // Authorize the user
        $user = $this->helper->authorizeUser($request);
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        // Validation rules for each item in the array
        $validator = Validator::make($request->all(), [
            'purchase_id' => 'required|string',
            'purchase_group_id' => 'required|string',
            'inventory_id' => 'required|string',
            'inventory_product_id' => 'required|string',
            'user_id_customer' => 'required|string',
            'quantity' => 'required|numeric|min:1',
            'eu_device' => 'required|string',
        ]);

        // Check if validation fails
        if ($validator->fails()) {
            return response()->json(
                [
                    'message' => $validator->errors(),
                ],
                Response::HTTP_UNPROCESSABLE_ENTITY
            );
        }

        // Validate Eu Device
        $result_validate_eu_device = $this->helper->validateEuDevice($request->eu_device);
        if ($result_validate_eu_device) {
            return $result_validate_eu_device;
        }


        // Start the transaction
        DB::beginTransaction();

        try {
            $decrypted_purchase_id = Crypt::decrypt($request->purchase_id);
            $decrypted_purchase_group_id = Crypt::decrypt($request->purchase_group_id);
            $decrypted_inventory_id = Crypt::decrypt($request->inventory_id);
            $decrypted_inventory_product_id = Crypt::decrypt($request->inventory_product_id);
            $decrypted_user_id_customer = Crypt::decrypt($request->user_id_customer);

            $purchase_count = PurchaseModel::where('purchase_group_id', $decrypted_purchase_group_id)
                ->where('user_id_customer', $decrypted_user_id_customer)
                ->where('user_id_menu', $user->user_id)
                ->where('inventory_id', $decrypted_inventory_id)
                ->where('inventory_product_id', $decrypted_inventory_product_id)
                ->count();

            // Add qty
            if ($request->quantity > $purchase_count) {
                $qty = $request->quantity - $purchase_count;

                $inventory_product = InventoryProductModel::where('inventory_product_id', $decrypted_inventory_product_id)
                    ->where('inventory_id', $decrypted_inventory_id)
                    ->first();

                if (!$inventory_product) {
                    return response()->json(['message' => 'Inventory Product ID not found'], Response::HTTP_NOT_FOUND);
                }

                if ($inventory_product->stocks < $qty) {
                    return response()->json(['message' => 'Failed to increment out of stocks'], Response::HTTP_UNPROCESSABLE_ENTITY);
                }

                while ($ctr < $qty) {
                    $update_stock = $inventory_product->update([
                        'stocks' => $inventory_product->stocks - 1,
                    ]);

                    if (!$update_stock) {
                        DB::rollBack();
                        return response()->json(
                            [
                                'message' => 'Failed to update stock. Please try again later.',
                            ],
                            Response::HTTP_INTERNAL_SERVER_ERROR
                        );
                    }

                    $purchase = PurchaseModel::where('purchase_id', $decrypted_purchase_id)
                        ->where('purchase_group_id', $decrypted_purchase_group_id)
                        ->where('inventory_id', $decrypted_inventory_id)
                        ->where('inventory_product_id', $decrypted_inventory_product_id)
                        ->where('user_id_customer', $decrypted_user_id_customer)
                        ->where('user_id_menu', $user->user_id)
                        ->first();

                    if (!$purchase) {
                        DB::rollBack();
                        return response()->json(
                            [
                                'message' => 'No data found',
                            ],
                            Response::HTTP_INTERNAL_SERVER_ERROR
                        );
                    }

                    $arr_store = [];
                    foreach ($this->fillable_attr_purchase->arrAddQtyPurchases() as $arrAddQtyPurchases) {
                        $arr_store[$arrAddQtyPurchases] = $purchase->$arrAddQtyPurchases;
                    }

                    // Create a new purchase using the attributes of $purchase
                    $created = PurchaseModel::create($arr_store);
                    if (!$created) {
                        DB::rollBack();
                        return response()->json(
                            [
                                'message' => 'Failed to store purchase',
                            ],
                            Response::HTTP_INTERNAL_SERVER_ERROR
                        );
                    }

                    // Update the purchase_id with the correct format
                    $update_purchase_id = $created->update([
                        'purchase_id' => 'purchase_id-' . $created->id,
                    ]);
                    if (!$update_purchase_id) {
                        DB::rollBack();
                        return response()->json(
                            ['message' => 'Failed to update purchase ID'],
                            Response::HTTP_INTERNAL_SERVER_ERROR
                        );
                    }

                    $total_amount_payment = $this->totalAmountPayment($decrypted_purchase_group_id, $decrypted_user_id_customer);
                    $update_payment = PaymentModel::where('user_id', $decrypted_user_id_customer)
                        ->where('purchase_group_id', $decrypted_purchase_group_id)
                        ->first()
                        ->update([
                            'total_amount' => $total_amount_payment['total_amount'],
                            'total_discounted_amount' => $total_amount_payment['total_discounted_amount'],
                        ]);

                    // Check if payment record exists
                    if (!$update_payment) {
                        DB::rollBack();
                        return response()->json(
                            ['message' => 'Failed to update total amount'],
                            Response::HTTP_NOT_FOUND
                        );
                    }

                    $arr_add_purchase[] = $purchase;
                    $ctr++;
                }

                $arr_log_details['fields'] = $arr_add_purchase;

                // Arr Data Logs
                $arr_data_logs = [
                    'user_device' => $request->eu_device,
                    'user_id' => $user->user_id,
                    'is_sensitive' => 0,
                    'is_history' => 0,
                    'log_details' => $arr_log_details,
                    'user_action' => 'ADD QUANTITY ITEM',
                ];

                // Logs
                $log_result = $this->helper->log($request, $arr_data_logs);
                if ($log_result->getStatusCode() !== Response::HTTP_OK) {
                    DB::rollBack();
                    return $log_result;
                }

                // Commit the transaction
                DB::commit();

                return response()->json(
                    [
                        'message' => 'Success add on item',
                        // 'parameter' => $purchase
                    ],
                    Response::HTTP_OK
                );
            }

            // Minus qty
            else if ($request->quantity < $purchase_count) {
                $qty = $purchase_count - $request->quantity;

                try {
                    $purchases = PurchaseModel::where('purchase_group_id', $decrypted_purchase_group_id)
                        ->where('user_id_customer', $decrypted_user_id_customer)
                        ->where('user_id_menu', $user->user_id)
                        ->where('inventory_id', $decrypted_inventory_id)
                        ->where('inventory_product_id', $decrypted_inventory_product_id)
                        ->get();

                    $inventory_product = InventoryProductModel::where('inventory_product_id', $decrypted_inventory_product_id)
                        ->where('inventory_id', $decrypted_inventory_id)
                        ->first();
                    if (!$inventory_product) {
                        return response()->json(['message' => 'Inventory Product ID not found'], Response::HTTP_NOT_FOUND);
                    }

                    $update_stock = $inventory_product->update([
                        'stocks' => $inventory_product->stocks + $qty,
                    ]);

                    if (!$update_stock) {
                        DB::rollBack();
                        return response()->json(
                            [
                                'message' => 'Failed to update stock. Please try again later.',
                            ],
                            Response::HTTP_INTERNAL_SERVER_ERROR
                        );
                    }

                    $ctr = 0; // Initialize the counter

                    foreach ($purchases as $purchase) {
                        if ($ctr >= $qty) {
                            break; // Exit the foreach loop if the required quantity is reached
                        }

                        if ($purchase->delete()) {
                            $arr_minus_purchase[] = $purchase;
                            $ctr++; // Increment the counter
                        } else {
                            DB::rollBack();
                            return response()->json(['message' => 'Failed to delete item.'], Response::HTTP_INTERNAL_SERVER_ERROR);
                        }
                    }

                    if ($ctr < $qty) {
                        DB::rollBack();
                        return response()->json(['message' => 'Not enough purchases to delete'], Response::HTTP_BAD_REQUEST);
                    }

                    $total_amount_payment = $this->totalAmountPayment($decrypted_purchase_group_id, $decrypted_user_id_customer);
                    $update_payment = PaymentModel::where('user_id', $decrypted_user_id_customer)
                        ->where('purchase_group_id', $decrypted_purchase_group_id)
                        ->first()
                        ->update([
                            'total_amount' => $total_amount_payment['total_amount'],
                            'total_discounted_amount' => $total_amount_payment['total_discounted_amount'],
                        ]);

                    // Check if payment record exists
                    if (!$update_payment) {
                        DB::rollBack();
                        return response()->json(
                            ['message' => 'Failed to update total amount'],
                            Response::HTTP_NOT_FOUND
                        );
                    }

                    $arr_log_details['fields'] = $arr_minus_purchase;

                    // Arr Data Logs
                    $arr_data_logs = [
                        'user_device' => $request->eu_device,
                        'user_id' => $user->user_id,
                        'is_sensitive' => 0,
                        'is_history' => 0,
                        'log_details' => $arr_log_details,
                        'user_action' => 'MINUS QUANTITY ITEM',
                    ];

                    // Logs
                    $log_result = $this->helper->log($request, $arr_data_logs);
                    if ($log_result->getStatusCode() !== Response::HTTP_OK) {
                        DB::rollBack();
                        return $log_result;
                    }

                    // Commit the transaction
                    DB::commit();

                    return response()->json(
                        [
                            'message' => 'Success minus on item',
                        ],
                        Response::HTTP_OK
                    );
                } catch (\Exception $e) {
                    // Rollback the transaction in case of any error
                    DB::rollBack();
                    return response()->json(['message' => $e->getMessage()], Response::HTTP_INTERNAL_SERVER_ERROR);
                }
            }
        } catch (\Exception $e) {
            // Rollback the transaction in case of any error
            DB::rollBack();
            return response()->json(['message' => $e->getMessage()], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    // public function minusQty(Request $request)
    // {
    //     $arr_minus_purchase = [];
    //     $ctr = 0;

    //     // Authorize the user
    //     $user = $this->helper->authorizeUser($request);
    //     if (empty($user->user_id)) {
    //         return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
    //     }

    //     // Validation rules for each item in the array
    //     $validator = Validator::make($request->all(), [
    //         'purchase_group_id' => 'required|string',
    //         'inventory_id' => 'required|string',
    //         'inventory_product_id' => 'required|string',
    //         'user_id_customer' => 'required|string',
    //         'eu_device' => 'required|string',
    //         'quantity' => 'required|numeric|min:1',
    //     ]);

    //     // Check if validation fails
    //     if ($validator->fails()) {
    //         return response()->json(
    //             [
    //                 'message' => $validator->errors(),
    //             ],
    //             Response::HTTP_UNPROCESSABLE_ENTITY
    //         );
    //     }

    //     // Validate Eu Device
    //     $result_validate_eu_device = $this->helper->validateEuDevice($request->eu_device);
    //     if ($result_validate_eu_device) {
    //         return $result_validate_eu_device;
    //     }

    //     $decrypted_purchase_group_id = Crypt::decrypt($request->purchase_group_id);
    //     $decrypted_inventory_id = Crypt::decrypt($request->inventory_id);
    //     $decrypted_inventory_product_id = Crypt::decrypt($request->inventory_product_id);
    //     $decrypted_user_id_customer = Crypt::decrypt($request->user_id_customer);

    //     // Start the transaction
    //     DB::beginTransaction();

    //     try {
    //         $purchases = PurchaseModel::where('purchase_group_id', $decrypted_purchase_group_id)
    //             ->where('user_id_customer', $decrypted_user_id_customer)
    //             ->where('user_id_menu', $user->user_id)
    //             ->where('inventory_id', $decrypted_inventory_id)
    //             ->where('inventory_product_id', $decrypted_inventory_product_id)
    //             ->get();

    //         $purchases_count = PurchaseModel::where('purchase_group_id', $decrypted_purchase_group_id)
    //             ->where('user_id_customer', $decrypted_user_id_customer)
    //             ->where('user_id_menu', $user->user_id)
    //             ->where('inventory_id', $decrypted_inventory_id)
    //             ->where('inventory_product_id', $decrypted_inventory_product_id)
    //             ->count();

    //         if ($purchases_count < $request->quantity) {
    //             return response()->json(['message' => 'Failed to decrement purchase. The quantity is greater than the purchased quantity.'], Response::HTTP_NOT_FOUND);
    //         }

    //         $inventory_product = InventoryProductModel::where('inventory_product_id', $decrypted_inventory_product_id)
    //             ->where('inventory_id', $decrypted_inventory_id)
    //             ->first();
    //         if (!$inventory_product) {
    //             return response()->json(['message' => 'Inventory Product ID not found'], Response::HTTP_NOT_FOUND);
    //         }

    //         $update_stock = $inventory_product->update([
    //             'stocks' => $inventory_product->stocks + $request->quantity,
    //         ]);

    //         if (!$update_stock) {
    //             DB::rollBack();
    //             return response()->json(
    //                 [
    //                     'message' => 'Failed to update stock. Please try again later.',
    //                 ],
    //                 Response::HTTP_INTERNAL_SERVER_ERROR
    //             );
    //         }

    //         foreach ($purchases as $purchase) {
    //             while ($ctr < $request->quantity) {
    //                 if (!$purchase) {
    //                     DB::rollBack();
    //                     return response()->json(
    //                         [
    //                             'message' => 'No data found',
    //                         ],
    //                         Response::HTTP_INTERNAL_SERVER_ERROR
    //                     );
    //                 }

    //                 if (!$purchase->delete()) {
    //                     DB::rollBack();
    //                     return response()->json(['message' => 'Failed to delete item.'], Response::HTTP_INTERNAL_SERVER_ERROR);
    //                 }

    //                 $arr_minus_purchase[] = $purchase;
    //                 $ctr++;  // Increment the counter
    //                 break;  // Break the while loop to proceed to the next purchase
    //             }

    //             if ($ctr >= $request->quantity) {
    //                 break;  // Exit the foreach loop if the required quantity is reached
    //             }
    //         }

    //         $total_amount_payment = $this->totalAmountPayment($decrypted_purchase_group_id, $decrypted_user_id_customer);
    //         $update_payment = PaymentModel::where('user_id', $decrypted_user_id_customer)
    //             ->where('purchase_group_id', $decrypted_purchase_group_id)
    //             ->first()
    //             ->update([
    //                 'total_amount' => $total_amount_payment['total_amount'],
    //                 'total_discounted_amount' => $total_amount_payment['total_discounted_amount'],
    //             ]);

    //         // Check if payment record exists
    //         if (!$update_payment) {
    //             DB::rollBack();
    //             return response()->json(
    //                 ['message' => 'Failed to update total amount'],
    //                 Response::HTTP_NOT_FOUND
    //             );
    //         }

    //         $arr_log_details['fields'] = $arr_minus_purchase;

    //         // Arr Data Logs
    //         $arr_data_logs = [
    //             'user_device' => $request->eu_device,
    //             'user_id' => $user->user_id,
    //             'is_sensitive' => 0,
    //             'is_history' => 0,
    //             'log_details' => $arr_log_details,
    //             'user_action' => 'MINUS QUANTITY ITEM',
    //         ];

    //         // Logs
    //         $log_result = $this->helper->log($request, $arr_data_logs);
    //         if ($log_result->getStatusCode() !== Response::HTTP_OK) {
    //             DB::rollBack();
    //             return $log_result;
    //         }

    //         // Commit the transaction
    //         DB::commit();

    //         return response()->json(
    //             [
    //                 'message' => 'Success minus on item',
    //             ],
    //             Response::HTTP_OK
    //         );
    //     } catch (\Exception $e) {
    //         // Rollback the transaction in case of any error
    //         DB::rollBack();
    //         return response()->json(['message' => $e->getMessage()], Response::HTTP_INTERNAL_SERVER_ERROR);
    //     }
    // }

    // public function addQty(Request $request)
    // {
    //     $arr_add_purchase = [];
    //     $ctr = 0;

    //     // Authorize the user
    //     $user = $this->helper->authorizeUser($request);
    //     if (empty($user->user_id)) {
    //         return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
    //     }

    //     // Validation rules for each item in the array
    //     $validator = Validator::make($request->all(), [
    //         'purchase_id' => 'required|string',
    //         'purchase_group_id' => 'required|string',
    //         'inventory_id' => 'required|string',
    //         'inventory_product_id' => 'required|string',
    //         'user_id_customer' => 'required|string',
    //         'quantity' => 'required|numeric|min:1',
    //         'eu_device' => 'required|string',
    //     ]);

    //     // Check if validation fails
    //     if ($validator->fails()) {
    //         return response()->json(
    //             [
    //                 'message' => $validator->errors(),
    //             ],
    //             Response::HTTP_UNPROCESSABLE_ENTITY
    //         );
    //     }

    //     // Validate Eu Device
    //     $result_validate_eu_device = $this->helper->validateEuDevice($request->eu_device);
    //     if ($result_validate_eu_device) {
    //         return $result_validate_eu_device;
    //     }

    //     // Start the transaction
    //     DB::beginTransaction();

    //     try {
    //         $decrypted_purchase_id = Crypt::decrypt($request->purchase_id);
    //         $decrypted_purchase_group_id = Crypt::decrypt($request->purchase_group_id);
    //         $decrypted_inventory_id = Crypt::decrypt($request->inventory_id);
    //         $decrypted_inventory_product_id = Crypt::decrypt($request->inventory_product_id);
    //         $decrypted_user_id_customer = Crypt::decrypt($request->user_id_customer);

    //         $inventory_product = InventoryProductModel::where('inventory_product_id', $decrypted_inventory_product_id)
    //             ->where('inventory_id', $decrypted_inventory_id)
    //             ->first();

    //         if (!$inventory_product) {
    //             return response()->json(['message' => 'Inventory Product ID not found'], Response::HTTP_NOT_FOUND);
    //         }

    //         if ($inventory_product->stocks < $request->quantity) {
    //             return response()->json(['message' => 'Failed to increment out of stocks'], Response::HTTP_UNPROCESSABLE_ENTITY);
    //         }

    //         while ($ctr < $request->quantity) {
    //             $update_stock = $inventory_product->update([
    //                 'stocks' => $inventory_product->stocks - 1,
    //             ]);

    //             if (!$update_stock) {
    //                 DB::rollBack();
    //                 return response()->json(
    //                     [
    //                         'message' => 'Failed to update stock. Please try again later.',
    //                     ],
    //                     Response::HTTP_INTERNAL_SERVER_ERROR
    //                 );
    //             }

    //             $purchase = PurchaseModel::where('purchase_id', $decrypted_purchase_id)
    //                 ->where('purchase_group_id', $decrypted_purchase_group_id)
    //                 ->where('inventory_id', $decrypted_inventory_id)
    //                 ->where('inventory_product_id', $decrypted_inventory_product_id)
    //                 ->where('user_id_customer', $decrypted_user_id_customer)
    //                 ->where('user_id_menu', $user->user_id)
    //                 ->first();

    //             if (!$purchase) {
    //                 DB::rollBack();
    //                 return response()->json(
    //                     [
    //                         'message' => 'No data found',
    //                     ],
    //                     Response::HTTP_INTERNAL_SERVER_ERROR
    //                 );
    //             }

    //             $arr_store = [];
    //             foreach ($this->fillable_attr_purchase->arrAddQtyPurchases() as $arrAddQtyPurchases) {
    //                 $arr_store[$arrAddQtyPurchases] = $purchase->$arrAddQtyPurchases;
    //             }

    //             // Create a new purchase using the attributes of $purchase
    //             $created = PurchaseModel::create($arr_store);
    //             if (!$created) {
    //                 DB::rollBack();
    //                 return response()->json(
    //                     [
    //                         'message' => 'Failed to store purchase',
    //                     ],
    //                     Response::HTTP_INTERNAL_SERVER_ERROR
    //                 );
    //             }

    //             // Update the purchase_id with the correct format
    //             $update_purchase_id = $created->update([
    //                 'purchase_id' => 'purchase_id-' . $created->id,
    //             ]);
    //             if (!$update_purchase_id) {
    //                 DB::rollBack();
    //                 return response()->json(
    //                     ['message' => 'Failed to update purchase ID'],
    //                     Response::HTTP_INTERNAL_SERVER_ERROR
    //                 );
    //             }

    //             $total_amount_payment = $this->totalAmountPayment($decrypted_purchase_group_id, $decrypted_user_id_customer);
    //             $update_payment = PaymentModel::where('user_id', $decrypted_user_id_customer)
    //                 ->where('purchase_group_id', $decrypted_purchase_group_id)
    //                 ->first()
    //                 ->update([
    //                     'total_amount' => $total_amount_payment['total_amount'],
    //                     'total_discounted_amount' => $total_amount_payment['total_discounted_amount'],
    //                 ]);

    //             // Check if payment record exists
    //             if (!$update_payment) {
    //                 DB::rollBack();
    //                 return response()->json(
    //                     ['message' => 'Failed to update total amount'],
    //                     Response::HTTP_NOT_FOUND
    //                 );
    //             }

    //             $arr_add_purchase[] = $purchase;
    //             $ctr++;
    //         }

    //         $arr_log_details['fields'] = $arr_add_purchase;

    //         // Arr Data Logs
    //         $arr_data_logs = [
    //             'user_device' => $request->eu_device,
    //             'user_id' => $user->user_id,
    //             'is_sensitive' => 0,
    //             'is_history' => 0,
    //             'log_details' => $arr_log_details,
    //             'user_action' => 'ADD QUANTITY ITEM',
    //         ];

    //         // Logs
    //         $log_result = $this->helper->log($request, $arr_data_logs);
    //         if ($log_result->getStatusCode() !== Response::HTTP_OK) {
    //             DB::rollBack();
    //             return $log_result;
    //         }

    //         // Commit the transaction
    //         DB::commit();

    //         return response()->json(
    //             [
    //                 'message' => 'Success add on item',
    //                 // 'parameter' => $purchase
    //             ],
    //             Response::HTTP_OK
    //         );
    //     } catch (\Exception $e) {
    //         // Rollback the transaction in case of any error
    //         DB::rollBack();
    //         return response()->json(['message' => $e->getMessage()], Response::HTTP_INTERNAL_SERVER_ERROR);
    //     }
    // }

    public function deleteQtyAll(Request $request)
    {
        $deleted_purchase_item = [];

        // Authorize the user
        $user = $this->helper->authorizeUser($request);
        if (empty($user->user_id)) {
            DB::rollBack();
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        // Validation rules for each item in the array
        $validator = Validator::make($request->all(), [
            'purchase_id' => 'required|array',
            'purchase_group_id' => 'required|string',
            'inventory_id' => 'required|string',
            'inventory_product_id' => 'required|string',
            'user_id_customer' => 'required|string',
            'eu_device' => 'required|string',
        ]);

        // Check if validation fails
        if ($validator->fails()) {
            return response()->json(
                [
                    'message' => $validator->errors(),
                ],
                Response::HTTP_UNPROCESSABLE_ENTITY
            );
        }

        // Validate Eu Device
        $result_validate_eu_device = $this->helper->validateEuDevice($request->eu_device);
        if ($result_validate_eu_device) {
            return $result_validate_eu_device;
        }

        // Start the transaction
        DB::beginTransaction();
        try {
            $decrypted_purchase_group_id = Crypt::decrypt($request->purchase_group_id);
            $decrypted_inventory_id = Crypt::decrypt($request->inventory_id);
            $decrypted_inventory_product_id = Crypt::decrypt($request->inventory_product_id);
            $decrypted_user_id_customer = Crypt::decrypt($request->user_id_customer);


            foreach ($request->purchase_id as $purchase_id) {
                $decrypted_purchase_id = Crypt::decrypt($purchase_id);

                $purchase = PurchaseModel::where('purchase_id', $decrypted_purchase_id)->first();
                if (!$purchase) {
                    DB::rollBack();
                    return response()->json(['message' => 'Purchase not found'], Response::HTTP_NOT_FOUND);
                }
                if (!$purchase->delete()) {
                    DB::rollBack();
                    return response()->json(['message' => 'Failed to delete purchase'], Response::HTTP_INTERNAL_SERVER_ERROR);
                }

                // Store the successfully deleted purchase ID
                $deleted_purchase_item[] = $purchase;
            }


            // Update stock after deleting all purchases
            $inventory_product = InventoryProductModel::where('inventory_product_id', $decrypted_inventory_product_id)
                ->where('inventory_id', $decrypted_inventory_id)
                ->first();
            if (!$inventory_product) {
                DB::rollBack();
                return response()->json(['message' => 'Inventory Product ID not found'], Response::HTTP_NOT_FOUND);
            }

            $inventory_product->update([
                'stocks' => max(0, $inventory_product->stock + count($deleted_purchase_item)),
            ]);

            $total_amount_payment = $this->totalAmountPaymentDeleteAll($decrypted_purchase_group_id, $decrypted_user_id_customer);
            $update_payment = PaymentModel::where('user_id', $decrypted_user_id_customer)
                ->where('purchase_group_id', $decrypted_purchase_group_id)
                ->first();

            if (!$update_payment) {
                DB::rollBack();
                return response()->json(['message' => 'Payment record not found'], Response::HTTP_NOT_FOUND);
            }

            $update_payment->update([
                'total_amount' => $total_amount_payment['total_amount'],
                'total_discounted_amount' => $total_amount_payment['total_discounted_amount'],
            ]);

            // Check if total amount is zero and then delete the payment record
            if ($total_amount_payment['total_amount'] == 0.00) {
                if (!$update_payment->delete()) {
                    DB::rollBack();
                    return response()->json(['message' => 'Failed to delete payment'], Response::HTTP_INTERNAL_SERVER_ERROR);
                }
            }

            $arr_log_details['fields'] = $deleted_purchase_item;

            // Arr Data Logs
            $arr_data_logs = [
                'user_device' => $request->eu_device,
                'user_id' => $user->user_id,
                'is_sensitive' => 0,
                'is_history' => 0,
                'log_details' => $arr_log_details,
                'user_action' => 'DELETE ALL QUANTITY SINGLE ITEM',
            ];

            // Logs
            $log_result = $this->helper->log($request, $arr_data_logs);
            if ($log_result->getStatusCode() !== Response::HTTP_OK) {
                DB::rollBack();
                return $log_result;
            }

            // Commit the transaction
            DB::commit();

            return response()->json(
                [
                    'message' => 'Purchase and Payment records deleted successfully',
                ],
                Response::HTTP_OK
            );
        } catch (\Exception $e) {
            // Rollback the transaction in case of any error
            DB::rollBack();
            return response()->json(['message' => $e->getMessage()], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    // public function updateQty(Request $request)
    // {
    //     $user_action = '';
    //     $status = 'NOT PAID';
    //     $ctr = 0;
    //     $arr_all_purchase = [];

    //     // Authorize the user
    //     $user = $this->helper->authorizeUser($request);
    //     if (empty($user->user_id)) {
    //         DB::rollBack();
    //         return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
    //     }

    //     // Validation rules for each item in the array
    //     $validator = Validator::make($request->all(), [
    //         'purchase_id' => 'required|string',
    //         'purchase_group_id' => 'required|string',
    //         'inventory_id' => 'required|string',
    //         'inventory_product_id' => 'required|string',
    //         'user_id_customer' => 'required|string',
    //         'quantity' => 'required|numeric|min:1',
    //         'eu_device' => 'required|string',
    //     ]);

    //     // Check if validation fails
    //     if ($validator->fails()) {
    //         return response()->json([
    //             'message' => $validator->errors(),
    //         ], Response::HTTP_UNPROCESSABLE_ENTITY);
    //     }


    //     // Start the transaction
    //     DB::beginTransaction();

    //     try {
    //         $decrypted_purchase_id = Crypt::decrypt($request->purchase_id);
    //         $decrypted_purchase_group_id = Crypt::decrypt($request->purchase_group_id);
    //         $decrypted_inventory_id = Crypt::decrypt($request->inventory_id);
    //         $decrypted_inventory_product_id = Crypt::decrypt($request->inventory_product_id);
    //         $decrypted_user_id_customer = Crypt::decrypt($request->user_id_customer);

    //         $inventory_product = InventoryProductModel::where('inventory_product_id', $decrypted_inventory_product_id)
    //             ->where('inventory_id', $decrypted_inventory_id)
    //             ->first();
    //         if (!$inventory_product) {
    //             return response()->json(['message' => 'Inventory Product ID not found'], Response::HTTP_NOT_FOUND);
    //         }

    //         if ($inventory_product->stocks < $request->quantity) {
    //             return response()->json(['message' => 'Failed to increment out of stocks'], Response::HTTP_UNPROCESSABLE_ENTITY);
    //         }

    //         $purchase = PurchaseModel::where('purchase_id', $decrypted_purchase_id)
    //             ->where('purchase_group_id', $decrypted_purchase_group_id)
    //             ->where('inventory_id', $decrypted_inventory_id)
    //             ->where('inventory_product_id', $decrypted_inventory_product_id)
    //             ->where('user_id_customer', $decrypted_user_id_customer)
    //             ->first();

    //         if (!$purchase) {
    //             DB::rollBack();
    //             return response()->json(['message' => 'Purchase not found'], Response::HTTP_NOT_FOUND);
    //         }

    //         $count = PurchaseModel::where('purchase_group_id', $decrypted_purchase_group_id)
    //             ->where('inventory_id', $decrypted_inventory_id)
    //             ->where('inventory_product_id', $decrypted_inventory_product_id)
    //             ->where('user_id_customer', $decrypted_user_id_customer)
    //             ->count();

    //         if ($request->quantity == $count) {
    //             return response()->json([
    //                 'message' => " The quantity remains unchanged. Please modify it."
    //             ], Response::HTTP_UNPROCESSABLE_ENTITY);
    //         } else if ($request->quantity > $count) {
    //             $user_action = 'ADD QUANTITY ON ITEM';
    //             do {
    //                 foreach ($this->fillable_attr_purchase->arrToStores() as $arrToStores) {
    //                     switch ($arrToStores) {
    //                         case 'user_id_customer':
    //                             $arr_store_fresh_create[$arrToStores] = $purchase->user_id_customer;
    //                             break;
    //                         case 'purchase_group_id':
    //                             $arr_store_fresh_create[$arrToStores] = $purchase->purchase_group_id;
    //                             break;
    //                         case 'user_id_menu':
    //                             $arr_store_fresh_create[$arrToStores] = $user->user_id;
    //                             break;
    //                         case 'status':
    //                             $arr_store_fresh_create[$arrToStores] = $status;
    //                             break;
    //                         default:
    //                             $arr_store_fresh_create[$arrToStores] = $purchase->$arrToStores;
    //                     }
    //                 }

    //                 // Create a new purchase record
    //                 $created_purchase = PurchaseModel::create($arr_store_fresh_create);
    //                 if (!$created_purchase) {
    //                     DB::rollBack();
    //                     return response()->json(
    //                         ['message' => 'Failed to store purchase'],
    //                         Response::HTTP_INTERNAL_SERVER_ERROR
    //                     );
    //                 }

    //                 // Update the unique I.D
    //                 $update_unique_id = $this->helper->updateUniqueId($created_purchase, $this->fillable_attr_purchase->idToUpdatePurchase(), $created_purchase->id);
    //                 if ($update_unique_id) {
    //                     DB::rollBack();
    //                     // Retun only if theres an error
    //                     return $update_unique_id;
    //                 }

    //                 // Minus Stock
    //                 $minus_stock = $this->minusStock($decrypted_inventory_product_id);
    //                 if ($minus_stock->getStatusCode() !== Response::HTTP_OK) {
    //                     DB::rollBack();
    //                     return $minus_stock;
    //                 }
    //                 $total_amount_payment = $this->totalAmountPayment($created_purchase->purchase_group_id, $created_purchase->user_id_customer);

    //                 // Update the payment record
    //                 $payment = PaymentModel::where('purchase_group_id', $created_purchase->purchase_group_id)->first();
    //                 if (!$payment) {
    //                     DB::rollBack();
    //                     return response()->json(
    //                         ['message' => 'Payment record not found'],
    //                         Response::HTTP_NOT_FOUND
    //                     );
    //                 }

    //                 $payment->update([
    //                     'total_amount' => $total_amount_payment['total_amount'],
    //                     'total_discounted_amount' => $total_amount_payment['total_discounted_amount'],
    //                 ]);

    //                 // Re-fetch the updated payment record
    //                 $updated_payment = PaymentModel::where('id', $payment->id)->first();

    //                 // Store logs for create Purchase
    //                 $arr_all_purchase['purchase'][] = $created_purchase;
    //                 // Store logs for update Payment
    //                 $arr_all_purchase['payment'][] = $updated_payment;

    //                 $ctr++;
    //             } while ($count > $ctr);
    //         } else if ($request->quantity < $count) {
    //             $user_action = 'MINUS QUANTITY ON ITEM';
    //             $take = 0;
    //             $take = $request->quantity;
    //             $purchases = PurchaseModel::where('purchase_group_id', $decrypted_purchase_group_id)
    //                 ->where('inventory_id', $decrypted_inventory_id)
    //                 ->where('inventory_product_id', $decrypted_inventory_product_id)
    //                 ->where('user_id_customer', $decrypted_user_id_customer)
    //                 ->take($take)
    //                 ->get();

    //             // Check if any purchases are found
    //             if ($purchases->isEmpty()) {
    //                 return response()->json(['message' => 'No purchases found for the given criteria'], Response::HTTP_NOT_FOUND);
    //             }

    //             foreach ($purchases as $purchase_data) {
    //                 $purchase = PurchaseModel::where('purchase_id', $purchase_data->purchase_id)->first();
    //                 if (!$purchase) {
    //                     DB::rollBack();
    //                     return response()->json(['message' => 'Purchase not found'], Response::HTTP_NOT_FOUND);
    //                 }
    //                 if (!$purchase->delete()) {
    //                     DB::rollBack();
    //                     return response()->json(['message' => 'Failed to delete purchase'], Response::HTTP_INTERNAL_SERVER_ERROR);
    //                 }

    //                 // Update stock after deleting all purchases
    //                 $inventory_product = InventoryProductModel::where('inventory_product_id', $purchase_data->inventory_product_id)
    //                     ->where('inventory_id', $purchase_data->inventory_id)
    //                     ->first();
    //                 if (!$inventory_product) {
    //                     DB::rollBack();
    //                     return response()->json(['message' => 'Inventory Product ID not found'], Response::HTTP_NOT_FOUND);
    //                 }

    //                 $inventory_product->update([
    //                     'stocks' =>  $inventory_product->stocks + count($arr_all_purchase),
    //                 ]);

    //                 $total_amount_payment = $this->totalAmountPaymentDeleteAll($purchase_data->purchase_group_id, $purchase_data->user_id_customer);
    //                 $update_payment = PaymentModel::where('user_id', $purchase_data->user_id_customer)
    //                     ->where('purchase_group_id', $purchase_data->purchase_group_id)
    //                     ->first();

    //                 if (!$update_payment) {
    //                     DB::rollBack();
    //                     return response()->json(['message' => 'Payment record not found'], Response::HTTP_NOT_FOUND);
    //                 }

    //                 $update_payment->update([
    //                     'total_amount' => $total_amount_payment['total_amount'],
    //                     'total_discounted_amount' => $total_amount_payment['total_discounted_amount'],
    //                 ]);

    //                 // Check if total amount is zero and then delete the payment record
    //                 if ($total_amount_payment['total_amount'] == 0.00) {
    //                     if (!$update_payment->delete()) {
    //                         DB::rollBack();
    //                         return response()->json(['message' => 'Failed to delete payment'], Response::HTTP_INTERNAL_SERVER_ERROR);
    //                     }
    //                 }

    //                 // Store logs for create Purchase
    //                 $arr_all_purchase['purchase'][] = $purchase;
    //                 // Store logs for update Payment
    //                 $arr_all_purchase['payment'][] = $update_payment;
    //             }
    //         }


    //         $arr_log_details['fields'] = $arr_all_purchase;

    //         // Arr Data Logs
    //         $arr_data_logs = [
    //             'user_device' => $request->eu_device,
    //             'user_id' => $user->user_id,
    //             'is_sensitive' => 0,
    //             'is_history' => 0,
    //             'log_details' => $arr_log_details,
    //             'user_action' => $user_action,
    //         ];

    //         // Logs
    //         $log_result = $this->helper->log($request, $arr_data_logs);
    //         if ($log_result->getStatusCode() !== Response::HTTP_OK) {
    //             DB::rollBack();
    //             return $log_result;
    //         }

    //         // Commit the transaction
    //         DB::commit();

    //         return response()->json([
    //             'message' => 'Quantity updated successfully.',
    //         ], Response::HTTP_OK);
    //     } catch (\Exception $e) {
    //         // Rollback the transaction in case of any error
    //         DB::rollBack();
    //         return response()->json(['message' => $e->getMessage()], Response::HTTP_INTERNAL_SERVER_ERROR);
    //     }
    // }

    public function getUserIdMenuCustomer(Request $request)
    {
        // Initialize array to store purchase information
        $grouped_purchases = [];
        $crud_settings = $this->fillable_attr_purchase->getApiAccountCrudSettings();

        // Authorize the user
        $user = $this->helper->authorizeUser($request);
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        // Fetch purchases
        $purchases = PurchaseModel::where('user_id_menu', $user->user_id)
            ->where('status', 'NOT PAID')
            ->orderBy('created_at', 'asc') // Add this line to sort by 'created_at' in ascending order
            ->get();


        // Loop through purchases 
        foreach ($purchases as $purchase) {
            // Generate a key based on the user_id_customer
            $key = $purchase->user_id_customer;

            // Check if the key already exists in the grouped purchases array
            if (isset($grouped_purchases[$key])) {
                // If the key exists, check if the same purchase details already exist
                $found = false;
                foreach ($grouped_purchases[$key] as &$grouped_purchase) {
                    if (
                        $grouped_purchase['purchase_group_id'] === $purchase->purchase_group_id &&
                        $grouped_purchase['inventory_id'] === $purchase->inventory_id &&
                        $grouped_purchase['inventory_product_id'] === $purchase->inventory_product_id &&
                        $grouped_purchase['customer_name'] === $purchase->customer_name &&
                        $grouped_purchase['item_code'] === $purchase->item_code &&
                        $grouped_purchase['name'] === $purchase->name &&
                        $grouped_purchase['category'] === $purchase->category &&
                        $grouped_purchase['design'] === $purchase->design &&
                        $grouped_purchase['size'] === $purchase->size &&
                        $grouped_purchase['color'] === $purchase->color &&
                        $grouped_purchase['retail_price'] === $purchase->retail_price &&
                        $grouped_purchase['discounted_price'] === $purchase->discounted_price
                    ) {
                        // Initialize arr_purchase_id if it's not already set
                        if (!isset($grouped_purchase['arr_purchase_id'])) {
                            $grouped_purchase['arr_purchase_id'] = [];
                        }
                        $grouped_purchase['arr_purchase_id'][] = $purchase->purchase_id;

                        if (!isset($grouped_purchase['action'])) {
                            $grouped_purchase['action'] = [];
                        }
                        $grouped_purchase['action'] = $this->helper->formatApi(
                            $crud_settings['prefix'],
                            $crud_settings['api_with_payloads'],
                            $crud_settings['method'],
                            $crud_settings['button_names'],
                            $crud_settings['icons'],
                            $crud_settings['actions']
                        );

                        // If the same purchase details exist, increment the count and update total_price
                        $grouped_purchase['count']++;
                        if ($purchase->discounted_price != 0) {
                            $grouped_purchase['total_price'] = $purchase->discounted_price * $grouped_purchase['count'];
                        } else {
                            $grouped_purchase['total_price'] = $purchase->retail_price * $grouped_purchase['count'];
                        }

                        $found = true;
                        break;
                    }
                }
                // If the same purchase details not found, add the new purchase details
                if (!$found) {
                    $total_price = ($purchase->discounted_price != 0) ? $purchase->discounted_price : $purchase->retail_price;
                    $grouped_purchases[$key][] = [
                        'purchase_id' => $purchase->purchase_id,
                        'purchase_group_id' => $purchase->purchase_group_id,
                        'user_id_customer' => $purchase->user_id_customer,
                        'inventory_id' => $purchase->inventory_id,
                        'inventory_product_id' => $purchase->inventory_product_id,
                        'customer_name' => $purchase->customer_name,
                        'item_code' => $purchase->item_code,
                        'name' => $purchase->name,
                        'category' => $purchase->category,
                        'design' => $purchase->design,
                        'size' => $purchase->size,
                        'color' => $purchase->color,
                        'retail_price' => $purchase->retail_price,
                        'discounted_price' => $purchase->discounted_price,
                        'count' => 1,
                        'total_price' => $total_price,
                        'arr_purchase_id' => [$purchase->purchase_id], // Initialize arr_purchase_id with the first purchase ID
                    ];
                }
            } else {
                // If the key doesn't exist, initialize a new customer's purchases array    
                $total_price = ($purchase->discounted_price != 0) ? $purchase->discounted_price : $purchase->retail_price;
                $grouped_purchases[$key][] = [
                    'purchase_id' => $purchase->purchase_id,
                    'purchase_group_id' => $purchase->purchase_group_id,
                    'user_id_customer' => $purchase->user_id_customer,
                    'inventory_id' => $purchase->inventory_id,
                    'inventory_product_id' => $purchase->inventory_product_id,
                    'customer_name' => $purchase->customer_name,
                    'item_code' => $purchase->item_code,
                    'name' => $purchase->name,
                    'category' => $purchase->category,
                    'design' => $purchase->design,
                    'size' => $purchase->size,
                    'color' => $purchase->color,
                    'retail_price' => $purchase->retail_price,
                    'discounted_price' => $purchase->discounted_price,
                    'count' => 1,
                    'total_price' => $total_price,
                    'arr_purchase_id' => [$purchase->purchase_id], // Initialize arr_purchase_id with the first purchase ID
                ];
            }
        }

        // Prepare an array to hold each customer's data as objects
        $formatted_data = [];

        // Add payment information and format as objects
        foreach ($grouped_purchases as $user_id_customer => $items) {
            $customer_data = new \stdClass(); // Create a new stdClass object for each customer
            $customer_data->customer_id = $user_id_customer;
            $customer_data->customer_name = $items[0]['customer_name'];

            $customer_data->purchase_group_id = Crypt::encrypt($items[0]['purchase_group_id']); // Add purchase_group_id
            $customer_data->user_id_customer = Crypt::encrypt($user_id_customer); // Add user_id_customer

            $customer_data->total_orders = count($items); // Calculate total_orders as the number of unique items
            $customer_data->payment = PaymentModel::where('purchase_group_id', $items[0]['purchase_group_id'])
                ->where('user_id', $user_id_customer)
                ->get()
                ->toArray();


            // Encrypt payment information
            foreach ($customer_data->payment as &$payment_info) {
                $customer_data->payment_id = Crypt::encrypt($payment_info['payment_id']); // Add payment_id

                $payment_info['payment_id'] = Crypt::encrypt($payment_info['payment_id']);
                $payment_info['user_id'] = Crypt::encrypt($payment_info['user_id']);
                $payment_info['purchase_group_id'] = Crypt::encrypt($payment_info['purchase_group_id']);
                $payment_info['voucher_id'] = Crypt::encrypt($payment_info['voucher_id']);
                unset($payment_info['id']);
            }

            $customer_data->items = [];

            // Add items and format each as an object
            foreach ($items as $item) {
                $formatted_item = new \stdClass();
                $formatted_item->purchase_id = Crypt::encrypt($item['purchase_id']);
                $formatted_item->purchase_group_id = Crypt::encrypt($item['purchase_group_id']);
                $formatted_item->user_id_customer = Crypt::encrypt($item['user_id_customer']);
                $formatted_item->inventory_id = Crypt::encrypt($item['inventory_id']);
                $formatted_item->inventory_product_id = Crypt::encrypt($item['inventory_product_id']);
                $formatted_item->item_code = $item['item_code'];
                $formatted_item->name = $item['name'];
                $formatted_item->category = $item['category'];
                $formatted_item->design = $item['design'];
                $formatted_item->size = $item['size'];
                $formatted_item->color = $item['color'];
                $formatted_item->retail_price = $item['retail_price'];
                $formatted_item->discounted_price = $item['discounted_price'];
                $formatted_item->count = $item['count'];
                $formatted_item->total_price = $item['total_price'];
                $formatted_item->stocks = InventoryProductModel::where('inventory_product_id', $item['inventory_product_id'])
                    ->first()
                    ->stocks;


                // Encrypt arr_purchase_id
                $encrypted_purchase_ids = [];
                foreach ($item['arr_purchase_id'] as $purchase_id) {
                    $encrypted_purchase_ids[] = Crypt::encrypt($purchase_id);
                }
                $formatted_item->arr_purchase_id = $encrypted_purchase_ids;

                $customer_data->items[] = $formatted_item;
            }

            $formatted_data[] = $customer_data;
        }

        // Prepare response
        $response_data = [
            'message' => 'Data retrieved successfully',
            'data' => $formatted_data,
        ];

        return response()->json($response_data, Response::HTTP_OK);
    }

    public function updateCustomerName(Request $request)
    {
        // Authorize the user
        $user = $this->helper->authorizeUser($request);
        if (empty($user->user_id)) {
            DB::rollBack();
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        // Validation rules for each item in the array
        $validator = Validator::make($request->all(), [
            'purchase_group_id' => 'required|string',
            'user_id_customer' => 'required|string',
            'customer_name' => 'required|string',
            'eu_device' => 'required|string',
        ]);

        // Check if validation fails
        if ($validator->fails()) {
            return response()->json([
                'message' => $validator->errors(),
            ], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        // Start the transaction
        DB::beginTransaction();

        try {
            $decrypted_purchase_group_id = Crypt::decrypt($request->purchase_group_id);
            $decrypted_user_id_customer = Crypt::decrypt($request->user_id_customer);

            $purchases = PurchaseModel::where('purchase_group_id', $decrypted_purchase_group_id)
                ->where('user_id_customer', $decrypted_user_id_customer)
                ->get();

            if (!$purchases) {
                return response()->json(['message' => 'Purchase not found'], Response::HTTP_NOT_FOUND);
            }

            foreach ($purchases as $purchase) {
                // Get the changes of the fields
                $result_changes_item_for_logs = $this->helper->updateLogsOldNew($purchase, $this->fillable_attr_purchase->arrUpdateCustomerName(), $request->all(), '');
                $changes_for_logs[] = [
                    'purchase_id' => $purchase->purchase_id,
                    'purchase_group_id' => $decrypted_purchase_group_id,
                    'user_id_customer' => $decrypted_user_id_customer,
                    'fields' => $result_changes_item_for_logs,
                ];

                // Check if there's Changes Logs
                $result_changes_logs = $this->helper->checkIfTheresChangesLogs($changes_for_logs);
                if ($result_changes_logs) {
                    DB::rollBack();
                    return $result_changes_logs;
                }

                // Update Multiple Data
                $result_update_multi_data = $this->helper->arrUpdateMultipleData($purchase, $this->fillable_attr_purchase->arrUpdateCustomerName(), $request->all(), '');
                if ($result_update_multi_data) {
                    DB::rollBack();
                    return $result_update_multi_data;
                }

                if (!$purchase) {
                    DB::rollBack();
                    return response()->json(['message' => 'Failed to update'], Response::HTTP_INTERNAL_SERVER_ERROR);
                }

                $arr_log_details['fields'] = $changes_for_logs;
            }


            // Arr Data Logs
            $arr_data_logs = [
                'user_device' => $request->eu_device,
                'user_id' => $user->user_id,
                'is_sensitive' => 0,
                'is_history' => 0,
                'log_details' => $arr_log_details,
                'user_action' =>  'UPDATE CUSTOMER NAME',
            ];

            // Logs
            $log_result = $this->helper->log($request, $arr_data_logs);
            if ($log_result->getStatusCode() !== Response::HTTP_OK) {
                DB::rollBack();
                return $log_result;
            }

            // Commit the transaction
            DB::commit();

            return response()->json([
                'message' => 'Success update customer name',
            ], Response::HTTP_OK);
        } catch (\Exception $e) {
            // Rollback the transaction in case of any error
            DB::rollBack();
            return response()->json(['message' => $e->getMessage()], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    public function deleteCustomer(Request $request)
    {
        $arr_log_details = [];

        // Authorize the user
        $user = $this->helper->authorizeUser($request);
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        // Validation rules for each item in the array
        $validator = Validator::make($request->all(), [
            'payment_id' => 'required|string',
            'user_id' => 'required|string',
            'purchase_group_id' => 'required|string',
            'eu_device' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json(['message' => $validator->errors()], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        // Validate eu_device
        $result_validate_eu_device = $this->helper->validateEuDevice($request->eu_device);
        if ($result_validate_eu_device) {
            return $result_validate_eu_device;
        }

        DB::beginTransaction();

        try {
            $decrypted_payment_id = Crypt::decrypt($request->payment_id);
            $decrypted_user_id = Crypt::decrypt($request->user_id);
            $decrypted_purchase_group_id = Crypt::decrypt($request->purchase_group_id);

            $payment = PaymentModel::where('payment_id', $decrypted_payment_id)
                ->where('payment_id', $decrypted_payment_id)
                ->where('user_id', $decrypted_user_id)
                ->where('purchase_group_id', $decrypted_purchase_group_id)
                ->first();

            $arr_log_details['payment']['fields'] = $payment;

            if (!$payment) {
                return response()->json(['message' => 'Data not found'], Response::HTTP_NOT_FOUND);
            }

            $purchases = PurchaseModel::where('user_id_customer', $decrypted_user_id)
                ->where('purchase_group_id', $decrypted_purchase_group_id)
                ->get();

            foreach ($purchases as $purchase) {
                $inventory_product = InventoryProductModel::where('inventory_id', $purchase->inventory_id)
                    ->where('inventory_product_id', $purchase->inventory_product_id)
                    ->first();

                $update_stock = $inventory_product->update([
                    'stocks' => $inventory_product->stocks + 1,
                ]);

                if (!$update_stock) {
                    DB::rollBack();
                    return response()->json(['message' => 'Failed to update stock'], Response::HTTP_UNPROCESSABLE_ENTITY);
                }

                $arr_log_details['items']['fields'][] = $purchase;

                // Delete the user
                if (!$purchase->delete()) {
                    DB::rollBack();
                    return response()->json(['message' => 'Failed to delete purchase'], Response::HTTP_UNPROCESSABLE_ENTITY);
                }
            }

            // Delete the payment
            if (!$payment->delete()) {
                DB::rollBack();
                return response()->json(['message' => 'Failed to delete payment'], Response::HTTP_UNPROCESSABLE_ENTITY);
            }

            $eu_device = $request->input('eu_device');

            // Arr Data Logs
            $arr_data_logs = [
                'user_device' => $eu_device,
                'user_id' => $user->user_id,
                'is_sensitive' => 0,
                'is_history' => 0,
                'log_details' => $arr_log_details,
                'user_action' => 'DELETE CUSTOMER',
            ];

            // Logs
            $log_result = $this->helper->log($request, $arr_data_logs);
            if ($log_result->getStatusCode() !== Response::HTTP_OK) {
                DB::rollBack();
                return $log_result;
            }

            DB::commit();

            return response()->json([
                'message' => 'Successfully deleted data',
                // 'log_message' => $log_result
            ], Response::HTTP_OK);
        } catch (\Exception $e) {
            DB::rollBack();
            return response()->json(['message' => $e->getMessage()], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    // CHILD store
    private function generateGroupPurchaseId()
    {
        // Retrieve the last customer ID from the database
        $last_purchase = PurchaseModel::latest()->first();

        if ($last_purchase) {
            // Extract the numeric part of the last customer ID
            $customer_id = intval(substr($last_purchase->purchase_group_id, strrpos($last_purchase->purchase_group_id, '-') + 1));
            // Increment the numeric part by 1
            $new_purchase = 'purchase_group_id-' . ($customer_id + 1);
        } else {
            // If no existing customer IDs are found, start with 1
            $new_purchase = 'purchase_group_id-1';
        }

        return $new_purchase;
    }

    // CHILD store
    private function generateCustomerId()
    {
        // Retrieve the last customer ID from the database
        $last_customer = PurchaseModel::latest()->first();

        if ($last_customer) {
            // Extract the numeric part of the last customer ID
            $customer_id = intval(substr($last_customer->user_id_customer, strrpos($last_customer->user_id_customer, '-') + 1));
            // Increment the numeric part by 1
            $new_customer_id = 'customer-' . ($customer_id + 1);
        } else {
            // If no existing customer IDs are found, start with 1
            $new_customer_id = 'customer-1';
        }

        return $new_customer_id;
    }

    // CHILD store
    private function totalAmountPayment($purchase_group_id, $customer_id)
    {
        $total_amount = 0.00;
        $total_discounted_amount = 0.00;
        $arr_to_data = [];

        // Retrieve all purchases with the given purchase group ID  
        $purchases = PurchaseModel::where('purchase_group_id', $purchase_group_id)
            ->where('user_id_customer', $customer_id)
            ->get();

        foreach ($purchases as $purchase) {
            $inventory_product = InventoryProductModel::where('inventory_product_id', $purchase->inventory_product_id)
                ->where('inventory_id', $purchase->inventory_id)
                ->first();

            if (!$inventory_product) {
                // Inventory product not found for the current purchase
                return response()->json(['message' => 'Inventory product not found for purchase ID ' . $purchase->id], Response::HTTP_NOT_FOUND);
            }

            // Add the price of the inventory product to the total amount
            $total_amount += $purchase->discounted_price != 0.00 ? $purchase->discounted_price : $purchase->retail_price;
            $total_discounted_amount += $purchase->discounted_price;
        }

        $arr_to_data['total_amount'] = $total_amount;
        $arr_to_data['total_discounted_amount'] = $total_discounted_amount;

        // Return the total amount
        return $arr_to_data;
    }

    // CHILD store
    private function minusStock($inventory_product_id)
    {
        // Start the transaction
        DB::beginTransaction();

        try {
            $inventory_product = InventoryProductModel::where('inventory_product_id', $inventory_product_id)
                ->first();
            if (!$inventory_product) {
                // Rollback the transaction if inventory product not found
                DB::rollBack();
                return response()->json(['message' => 'Inventory Product ID not found'], Response::HTTP_NOT_FOUND);
            }

            // Perform the stock deduction
            $updated = $inventory_product->update([
                'stocks' => $inventory_product->stocks - 1,
            ]);

            if (!$updated) {
                // Rollback the transaction if failed to update stock
                DB::rollBack();
                return response()->json(['message' => 'Failed to update new stocks'], Response::HTTP_INTERNAL_SERVER_ERROR);
            }

            // Commit the transaction
            DB::commit();

            return response()->json(['message' => 'Stocks deducted successfully'], Response::HTTP_OK);
        } catch (\Exception $e) {
            // Rollback the transaction in case of any error
            DB::rollBack();
            return response()->json(['message' => $e->getMessage()], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    // CHILD deleteALl
    private function totalAmountPaymentDeleteAll($purchase_group_id, $customer_id)
    {
        $total_amount = 0.00;
        $total_discounted_amount = 0.00;
        $arr_to_data = [];

        // Start transaction
        DB::beginTransaction();

        // Retrieve all purchases with the given purchase group ID
        $purchases = PurchaseModel::where('purchase_group_id', $purchase_group_id)
            ->where('user_id_customer', $customer_id)
            ->get();

        if ($purchases->isEmpty()) {
            // Rollback the transaction if no purchases found
            DB::rollBack();
            $arr_to_data['total_amount'] = 0.00;
            $arr_to_data['total_discounted_amount'] = 0.00;

            return $arr_to_data;
        }

        foreach ($purchases as $purchase) {
            $inventory_product = InventoryProductModel::where('inventory_product_id', $purchase->inventory_product_id)
                ->first();

            if (!$inventory_product) {
                // Rollback the transaction if inventory product not found for any purchase
                DB::rollBack();
                return response()->json(['message' => 'Inventory product not found for purchase ID ' . $purchase->id], Response::HTTP_NOT_FOUND);
            }

            // Add the price of the inventory product to the total amount
            $total_amount += $purchase->discounted_price != 0.00 ? $purchase->discounted_price : $purchase->retail_price;
            $total_discounted_amount += $purchase->discounted_price;
        }

        // Commit the transaction if all purchases are processed successfully
        DB::commit();


        $arr_to_data['total_amount'] = $total_amount;
        $arr_to_data['total_discounted_amount'] = $total_discounted_amount;

        // Return the total amount
        return $arr_to_data;
    }

    /**
     * Display a listing of the resource.
     */
    public function index()
    {
        //
    }

    /**
     * Show the form for creating a new resource.
     */
    public function create()
    {
        //
    }

    /**
     * Display the specified resource.
     */
    public function show(string $id)
    {
        //
    }

    /**
     * Show the form for editing the specified resource.
     */
    public function edit(string $id)
    {
        //
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(Request $request, string $id)
    {
        //
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(string $id)
    {
        //
    }
}
