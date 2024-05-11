<?php

namespace App\Http\Controllers;

use App\Models\PaymentModel;
use Illuminate\Http\Request;
use App\Models\PurchaseModel;
use App\Models\InventoryProductModel;
use App\Http\Controllers\Helper\Helper;
use Illuminate\Support\Facades\Crypt;
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


        // Decrypted Variables
        $decrypted_inventory_product_id = $request->inventory_product_id != "" && $request->inventory_product_id != null ? Crypt::decrypt($request->inventory_product_id) : null;
        $decrypted_purchase_group_id = isset($request->purchase_group_id) &&  $request->purchase_group_id != "" && $request->purchase_group_id != null ? Crypt::decrypt($request->purchase_group_id) : null;
        $decrypted_purchase_user_id_customer = isset($request->user_id_customer) &&  $request->user_id_customer != "" && $request->user_id_customer != null ? Crypt::decrypt($request->user_id_customer) : null;

        $inventory_product = InventoryProductModel::where('inventory_product_id', $decrypted_inventory_product_id)
            ->first();
        if (!$inventory_product) {
            return response()->json(['message' => 'Inventory Product ID not found'], Response::HTTP_NOT_FOUND);
        }

        if ($inventory_product->stock < $request->quantity) {
            return response()->json(['message' => 'Sorry, can\'t add due to insufficient stock', 'stock' => $inventory_product->stock], Response::HTTP_UNPROCESSABLE_ENTITY);
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
                    return response()->json(
                        ['message' => 'Failed to store purchase'],
                        Response::HTTP_INTERNAL_SERVER_ERROR
                    );
                }

                // Update the unique I.D
                $update_unique_id = $this->helper->updateUniqueId($created_purchase, $this->fillable_attr_purchase->idToUpdatePurchase(), $created_purchase->id);
                if ($update_unique_id) {
                    return $update_unique_id;
                }

                // Minus Stock
                $minus_stock = $this->minusStock($decrypted_inventory_product_id);
                $total_amount_payment = $this->totalAmountPayment($decrypted_purchase_group_id, $created_purchase->user_id_customer);

                // Create a new payment record
                $update_payment = PaymentModel::where('purchase_group_id', $created_purchase->purchase_group_id)->first()->update([
                    'total_amount' => $total_amount_payment['total_amount'],
                    'total_discounted_amount' => $total_amount_payment['total_discounted_amount'],
                ]);

                // Check if payment record exists
                if (!$update_payment) {
                    return response()->json(
                        ['message' => 'Failed to update total amount'],
                        Response::HTTP_NOT_FOUND
                    );
                }

                $ctr++;
            } while ($ctr < $request->quantity);

            return response()->json(
                [
                    'message' => 'Purchase and Payment records stored successfully',
                    'message_stock' => $minus_stock,
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
                return response()->json(
                    ['message' => 'Failed generate purchase I.D'],
                    Response::HTTP_INTERNAL_SERVER_ERROR
                );
            }

            if ($new_customer_id == '') {
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
                        return response()->json(
                            ['message' => 'Failed to store purchase'],
                            Response::HTTP_INTERNAL_SERVER_ERROR
                        );
                    }

                    // Update the unique I.D Purchase
                    $update_unique_id = $this->helper->updateUniqueId($created_purchase, $this->fillable_attr_purchase->idToUpdatePurchase(), $created_purchase->id);
                    if ($update_unique_id) {
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
                        return response()->json(
                            ['message' => 'Failed to store payment'],
                            Response::HTTP_INTERNAL_SERVER_ERROR
                        );
                    }

                    // Update the unique I.D Payment
                    $update_unique_id = $this->helper->updateUniqueId($created_payment, $this->fillable_attr_purchase->idToUpdatePayment(), $created_payment->id);
                    if ($update_unique_id) {
                        return $update_unique_id;
                    }
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
                        return response()->json(
                            ['message' => 'Failed to store purchase'],
                            Response::HTTP_INTERNAL_SERVER_ERROR
                        );
                    }

                    // Update the unique I.D
                    $update_unique_id = $this->helper->updateUniqueId($created_purchase, $this->fillable_attr_purchase->idToUpdatePurchase(), $created_purchase->id);
                    if ($update_unique_id) {
                        // Retun only if theres an error
                        return $update_unique_id;
                    }

                    // Minus Stock
                    $minus_stock = $this->minusStock($decrypted_inventory_product_id);
                    $total_amount_payment = $this->totalAmountPayment($created_purchase->purchase_group_id, $created_purchase->user_id_customer);

                    // Create a new payment record
                    $update_payment = PaymentModel::where('purchase_group_id', $created_purchase->purchase_group_id)->first()->update([
                        'total_amount' => $total_amount_payment['total_amount'],
                        'total_discounted_amount' => $total_amount_payment['total_discounted_amount'],
                    ]);

                    // Check if payment record exists
                    if (!$update_payment) {
                        return response()->json(
                            ['message' => 'Failed to update total amount'],

                            Response::HTTP_NOT_FOUND
                        );
                    }
                }

                $ctr++;
            } while ($ctr < $request->quantity);


            return response()->json(
                [
                    'message' => 'Purchase and Payment records stored successfully',
                    'message_stock' => $minus_stock,
                ],
                Response::HTTP_OK
            );
        }
    }

    public function minusQty(Request $request)
    {
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

        $decrypted_purchase_id = Crypt::decrypt($request->purchase_id);
        $decrypted_purchase_group_id = Crypt::decrypt($request->purchase_group_id);
        $decrypted_inventory_id = Crypt::decrypt($request->inventory_id);
        $decrypted_inventory_product_id = Crypt::decrypt($request->inventory_product_id);
        $decrypted_user_id_customer = Crypt::decrypt($request->user_id_customer);

        $inventory_product = InventoryProductModel::where('inventory_product_id', $decrypted_inventory_product_id)
            ->where('inventory_id', $decrypted_inventory_id)
            ->first();
        if (!$inventory_product) {
            return response()->json(['message' => 'Inventory Product ID not found'], Response::HTTP_NOT_FOUND);
        }

        $update_stock = $inventory_product->update([
            'stock' => max(0, $inventory_product->stock + 1),
        ]);

        if (!$update_stock) {
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
            return response()->json(
                [
                    'message' => 'No data found',
                ],
                Response::HTTP_INTERNAL_SERVER_ERROR
            );
        }

        $purchase->delete();

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
            return response()->json(
                ['message' => 'Failed to update total amount'],
                Response::HTTP_NOT_FOUND
            );
        }

        return response()->json(
            [
                'message' => 'Success minus on item',
                'parameter' => $purchase
            ],
            Response::HTTP_OK
        );
    }

    public function addQty(Request $request)
    {
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

        $decrypted_purchase_id = Crypt::decrypt($request->purchase_id);
        $decrypted_purchase_group_id = Crypt::decrypt($request->purchase_group_id);
        $decrypted_inventory_id = Crypt::decrypt($request->inventory_id);
        $decrypted_inventory_product_id = Crypt::decrypt($request->inventory_product_id);
        $decrypted_user_id_customer = Crypt::decrypt($request->user_id_customer);

        $inventory_product = InventoryProductModel::where('inventory_product_id', $decrypted_inventory_product_id)
            ->where('inventory_id', $decrypted_inventory_id)
            ->first();
        if (!$inventory_product) {
            return response()->json(['message' => 'Inventory Product ID not found'], Response::HTTP_NOT_FOUND);
        }

        $update_stock = $inventory_product->update([
            'stock' => max(0, $inventory_product->stock - 1),
        ]);

        if (!$update_stock) {
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
            return response()->json(
                ['message' => 'Failed to update total amount'],
                Response::HTTP_NOT_FOUND
            );
        }

        return response()->json(
            [
                'message' => 'Success add on item',
                'parameter' => $purchase
            ],
            Response::HTTP_OK
        );
    }

    public function deleteAll(Request $request)
    {
        $deleted_purchase_id = [];

        // Authorize the user
        $user = $this->helper->authorizeUser($request);
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        // Validation rules for each item in the array
        $validator = Validator::make($request->all(), [
            'purchase_id' => 'required|array',
            'purchase_group_id' => 'required|string',
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

        $decrypted_purchase_group_id = Crypt::decrypt($request->purchase_group_id);
        $decrypted_inventory_id = Crypt::decrypt($request->inventory_id);
        $decrypted_inventory_product_id = Crypt::decrypt($request->inventory_product_id);
        $decrypted_user_id_customer = Crypt::decrypt($request->user_id_customer);

        foreach ($request->purchase_id as $purchase_id) {
            $decrypted_purchase_id = Crypt::decrypt($purchase_id);

            $purchase = PurchaseModel::where('purchase_id', $decrypted_purchase_id)->first();
            if (!$purchase) {
                return response()->json(['message' => 'Purchase not found'], Response::HTTP_NOT_FOUND);
            }
            if (!$purchase->delete()) {
                return response()->json(['message' => 'Failed to delete purchase'], Response::HTTP_INTERNAL_SERVER_ERROR);
            }
            // Store the successfully deleted purchase ID
            $deleted_purchase_id[] = $purchase_id;
        }

        // Update stock after deleting all purchases
        $inventory_product = InventoryProductModel::where('inventory_product_id', $decrypted_inventory_product_id)
            ->where('inventory_id', $decrypted_inventory_id)
            ->first();
        if (!$inventory_product) {
            return response()->json(['message' => 'Inventory Product ID not found'], Response::HTTP_NOT_FOUND);
        }

        $inventory_product->update([
            'stock' => max(0, $inventory_product->stock + count($deleted_purchase_id)),
        ]);

        $total_amount_payment = $this->totalAmountPaymentDeleteAll($decrypted_purchase_group_id, $decrypted_user_id_customer);
        $update_payment = PaymentModel::where('user_id', $decrypted_user_id_customer)
            ->where('purchase_group_id', $decrypted_purchase_group_id)
            ->first();

        if (!$update_payment) {
            return response()->json(['message' => 'Payment record not found'], Response::HTTP_NOT_FOUND);
        }

        $update_payment->update([
            'total_amount' => $total_amount_payment['total_amount'],
            'total_discounted_amount' => $total_amount_payment['total_discounted_amount'],
        ]);

        // Check if total amount is zero and then delete the payment record
        if ($total_amount_payment == 0) {
            if (!$update_payment->delete()) {
                return response()->json(['message' => 'Failed to delete payment'], Response::HTTP_INTERNAL_SERVER_ERROR);
            }
        }

        // Check if payment record exists
        if (!$update_payment) {
            return response()->json(
                ['message' => 'Failed to update total amount'],
                Response::HTTP_INTERNAL_SERVER_ERROR
            );
        }

        return response()->json(
            [
                'message' => 'Purchase and Payment records deleted successfully',
                'deleted_purchase_ids' => $deleted_purchase_id,
            ],
            Response::HTTP_OK
        );
    }

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
                            $crud_settings['methods'],
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

        // Add payment information
        $arr_purchase_customer = [];
        foreach ($grouped_purchases as $user_id_customer => $items) {
            $arr_purchase_customer[$user_id_customer]['payment'] = PaymentModel::where('purchase_group_id', $items[0]['purchase_group_id'])
                ->where('user_id', $user_id_customer)
                ->get()
                ->toArray();
            $arr_purchase_customer[$user_id_customer]['items'] = $items;
        }

        // Encrypt purchase IDs
        foreach ($arr_purchase_customer as $user_id_customer => &$customer_data) {
            foreach ($customer_data['items'] as &$item) {
                // Encrypt each purchase ID in arr_purchase_id
                $encrypted_purchase_ids = [];
                foreach ($item['arr_purchase_id'] as $purchase_id) {
                    $encrypted_purchase_ids[] = Crypt::encrypt($purchase_id);
                }
                $item['arr_purchase_id'] = $encrypted_purchase_ids;
            }
        }

        // Encrypt payment information
        foreach ($arr_purchase_customer as $user_id_customer => &$customer_data) {
            foreach ($customer_data['payment'] as &$payment_info) {
                $payment_info['payment_id'] = Crypt::encrypt($payment_info['payment_id']);
                $payment_info['user_id'] = Crypt::encrypt($payment_info['user_id']);
                $payment_info['purchase_group_id'] = Crypt::encrypt($payment_info['purchase_group_id']);
                $payment_info['voucher_id'] = Crypt::encrypt($payment_info['voucher_id']);
                unset($payment_info['id']);
            }
        }

        // Encrypt purchase items information
        foreach ($arr_purchase_customer as $user_id_customer => &$customer_data) {
            foreach ($customer_data['items'] as &$item) {
                $item['purchase_id'] = Crypt::encrypt($item['purchase_id']);
                $item['purchase_group_id'] = Crypt::encrypt($item['purchase_group_id']);
                $item['user_id_customer'] = Crypt::encrypt($item['user_id_customer']);
                $item['inventory_id'] = Crypt::encrypt($item['inventory_id']);
                $item['inventory_product_id'] = Crypt::encrypt($item['inventory_product_id']);
            }
        }


        // Prepare response
        $response_data = [
            'message' => 'Data retrieved successfully',
            'data' => $arr_purchase_customer,
        ];

        return response()->json($response_data, Response::HTTP_OK);
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

        if ($purchases->isEmpty()) {
            // No purchases found for the given purchase group ID
            return response()->json(['message' => 'No purchases found for the given purchase group ID'], Response::HTTP_NOT_FOUND);
        }

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
        $inventory_product = InventoryProductModel::where('inventory_product_id', $inventory_product_id)
            ->first();
        if (!$inventory_product) {
            return response()->json(['message' => 'Inventory Product ID not found'], Response::HTTP_NOT_FOUND);
        }

        // Perform the stock deduction
        $updated = $inventory_product->update([
            'stock' => $inventory_product->stock - 1,
        ]);

        if (!$updated) {
            return response()->json(['message' => 'Failed to update new stock'], Response::HTTP_NOT_FOUND);
        }

        return response()->json(['message' => 'Stock deducted successfully'], Response::HTTP_OK);
    }

    // CHILD deleteALl
    private function totalAmountPaymentDeleteAll($purchase_group_id, $customer_id)
    {
        $total_amount = 0.00;

        // Retrieve all purchases with the given purchase group ID
        $purchases = PurchaseModel::where('purchase_group_id', $purchase_group_id)
            ->where('user_id_customer', $customer_id)
            ->get();

        if ($purchases->isEmpty()) {
            return $total_amount;
        }

        foreach ($purchases as $purchase) {
            $inventory_product = InventoryProductModel::where('inventory_product_id', $purchase->inventory_product_id)
                ->where('inventory_group_id', $purchase->inventory_group_id)
                ->first();

            if (!$inventory_product) {
                // Inventory product not found for the current purchase
                return response()->json(['message' => 'Inventory product not found for purchase ID ' . $purchase->id], Response::HTTP_NOT_FOUND);
            }

            // Add the price of the inventory product to the total amount
            $total_amount += $purchase->discounted_price != 0.00 ? $purchase->discounted_price : $purchase->retail_price;
        }

        // Return the total amount
        return $total_amount;
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
