<?php

namespace App\Http\Controllers;

use App\Models\PaymentModel;
use Illuminate\Http\Request;
use App\Models\PurchaseModel;
use App\Models\InventoryProductModel;
use App\Http\Controllers\Helper\Helper;
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

        // $this->UnsetPurchaseStorePurchaseInventory = config('system.purchase.UnsetPurchaseStorePurchaseInventory');
        // $this->UnsetAddQtyPurchases = config('system.purchase.UnsetAddQtyPurchase');
        // $this->fillAttrPurchases = $purchaseModel->getFillableAttributes();
        // $this->fillAttrInventoryProducts = $inventoryProductModel->getFillableAttributes();
        // $this->fillAttrPayment = $paymentModel->getFillableAttributes();
    }

    public function store(Request $request)
    {
        $status = 'NOT PAID';
        $ctr = 0;
        $arr_data_fresh_create = [];
        $arr_store_fresh_create = [];

        // Authorize the user
        $user = $this->helper->authorizeUser($request);
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        // Validation rules for each item in the array
        $validator = Validator::make($request->all(), [
            'inventory_product_id' => 'required|string',
            'inventory_group_id' => 'required|string',
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

        $inventory_product = InventoryProductModel::where('inventory_product_id', $request->inventory_product_id)
            ->where('inventory_group_id', $request->inventory_group_id)
            ->first();
        if (!$inventory_product) {
            return response()->json(['message' => 'Inventory Product ID not found'], Response::HTTP_NOT_FOUND);
        }

        if ($inventory_product->stock < $request->quantity) {
            return response()->json(['message' => 'Sorry, can\'t add due to insufficient stock', 'stock' => $inventory_product->stock], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        // Add New Item on purchase_group_id
        if ($request->purchase_group_id != '' && $request->purchase_group_id != null && $request->user_id_customer != '' && $request->user_id_customer != null) {
            do {
                foreach ($this->fillable_attr_purchase->arrToStores() as $arrToStores) {
                    if ($arrToStores == 'user_id_customer') {
                        $arr_store_fresh_create[$arrToStores] = $request->user_id_customer;
                    } else if ($arrToStores == 'purchase_group_id') {
                        $arr_store_fresh_create[$arrToStores] = $request->purchase_group_id;
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

                // Update the purchase_id with the correct format
                $update_purchase_id = $created_purchase->update([
                    'purchase_id' => 'purchase_id-' . $created_purchase->id,
                ]);
                if (!$update_purchase_id) {
                    return response()->json(
                        ['message' => 'Failed to update purchase ID'],
                        Response::HTTP_INTERNAL_SERVER_ERROR
                    );
                }

                // Minus Stock
                $minus_stock = $this->minusStock($request->inventory_product_id, $request->inventory_group_id);
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
                $arr_data_fresh_create['group_purchase_id'] = $group_purchase_id;
                $arr_data_fresh_create['new_customer_id'] = $new_customer_id;

                // Fresh Create start 0
                if ($ctr == 0) {
                    foreach ($this->fillable_attr_purchase->arrToStores() as $arrToStores) {
                        if ($arrToStores == 'user_id_customer') {
                            $arr_store_fresh_create[$arrToStores] = $arr_data_fresh_create['newCustomerId'];
                        } else if ($arrToStores == 'purchase_group_id') {
                            $arr_store_fresh_create[$arrToStores] = $arr_data_fresh_create['groupPurchaseId'];
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

                    // Update the purchase_id with the correct format
                    $update_purchase_id = $created_purchase->update([
                        'purchase_id' => 'purchase_id-' . $created_purchase->id,
                    ]);
                    if (!$update_purchase_id) {
                        return response()->json(
                            ['message' => 'Failed to update purchase ID'],
                            Response::HTTP_INTERNAL_SERVER_ERROR
                        );
                    }

                    // Minus Stock
                    $minus_stock = $this->minusStock($request->inventory_product_id, $request->inventory_group_id);
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

                    // Update the payment_id with the correct format
                    $update_payment_id = $created_payment->update([
                        'payment_id' => 'payment_id-' . $created_payment->id,
                    ]);
                    if (!$update_payment_id) {
                        return response()->json(
                            ['message' => 'Failed to update payment ID'],
                            Response::HTTP_INTERNAL_SERVER_ERROR
                        );
                    }
                }
                // Fresh Create but greater 0 quantity 
                else {
                    foreach ($this->fillable_attr_purchase->arrToStores() as $arrToStores) {
                        if ($arrToStores == 'user_id_customer') {
                            $arr_store_fresh_create[$arrToStores] = $arr_data_fresh_create['newCustomerId'];
                        } else if ($arrToStores == 'purchase_group_id') {
                            $arr_store_fresh_create[$arrToStores] = $arr_data_fresh_create['groupPurchaseId'];
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

                    // Update the purchase_id with the correct format
                    $update_purchase_id = $created_purchase->update([
                        'purchase_id' => 'purchase_id-' . $created_purchase->id,
                    ]);
                    if (!$update_purchase_id) {
                        return response()->json(
                            ['message' => 'Failed to update purchase ID'],
                            Response::HTTP_INTERNAL_SERVER_ERROR
                        );
                    }

                    // Minus Stock
                    $minus_stock = $this->minusStock($request->inventory_product_id, $request->inventory_group_id);
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
            'inventory_product_id' => 'required|string',
            'inventory_group_id' => 'required|string',
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


        $inventory_product = InventoryProductModel::where('inventory_product_id', $request->inventory_product_id)
            ->where('inventory_group_id', $request->inventory_group_id)
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

        $purchase = PurchaseModel::where('purchase_id', $request->purchase_id)
            ->where('purchase_group_id', $request->purchase_group_id)
            ->where('inventory_product_id', $request->inventory_product_id)
            ->where('inventory_group_id', $request->inventory_group_id)
            ->where('user_id_customer', $request->user_id_customer)
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

        $total_amount_payment = $this->totalAmountPayment($request->purchase_group_id, $request->user_id_customer);
        $update_payment = PaymentModel::where('user_id', $request->user_id_customer)
            ->where('purchase_group_id', $request->purchase_group_id)
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
                'message' => 'Purchase and Payment records stored successfully',
                // 'message_minus_stock' => $resultMinusStock,
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
            'inventory_product_id' => 'required|string',
            'inventory_group_id' => 'required|string',
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

        $inventory_product = InventoryProductModel::where('inventory_product_id', $request->inventory_product_id)
            ->where('inventory_group_id', $request->inventory_group_id)
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

        $purchase = PurchaseModel::where('purchase_id', $request->purchase_id)
            ->where('purchase_group_id', $request->purchase_group_id)
            ->where('inventory_product_id', $request->inventory_product_id)
            ->where('inventory_group_id', $request->inventory_group_id)
            ->where('user_id_customer', $request->user_id_customer)
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

        // Convert $purchase to an array and remove unnecessary attributes
        // $purchaseAttributes = $purchase->toArray();
        // foreach ($this->UnsetAddQtyPurchases as $UnsetAddQtyPurchase) {
        //     unset($purchaseAttributes[$UnsetAddQtyPurchase]);
        // }

        // Create a new purchase using the attributes of $purchase
        $created_purchase = PurchaseModel::create($this->fillable_attr_purchase->arrAddQtyPurchases());

        if (!$created_purchase) {
            return response()->json(
                [
                    'message' => 'Failed to store purchase',
                ],
                Response::HTTP_INTERNAL_SERVER_ERROR
            );
        }

        // Update the purchase_id with the correct format
        $update_purchase_id = $created_purchase->update([
            'purchase_id' => 'purchase_id-' . $created_purchase->id,
        ]);
        if (!$update_purchase_id) {
            return response()->json(
                ['message' => 'Failed to update purchase ID'],
                Response::HTTP_INTERNAL_SERVER_ERROR
            );
        }

        $total_amount_payment = $this->totalAmountPayment($request->purchase_group_id, $request->user_id_customer);
        $update_payment = PaymentModel::where('user_id', $request->user_id_customer)
            ->where('purchase_group_id', $request->purchase_group_id)
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
                'message' => 'Purchase and Payment records stored successfully',
                // 'message_minus_stock' => $resultMinusStock,
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

        foreach ($request->purchase_id as $purchase_id) {
            $purchase = PurchaseModel::where('purchase_id', $purchase_id)->first();
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
        $inventory_product = InventoryProductModel::where('inventory_product_id', $purchase->inventory_product_id)
            ->where('inventory_group_id', $purchase->inventory_group_id)
            ->first();
        if (!$inventory_product) {
            return response()->json(['message' => 'Inventory Product ID not found'], Response::HTTP_NOT_FOUND);
        }

        $inventory_product->update([
            'stock' => max(0, $inventory_product->stock + count($deleted_purchase_id)),
        ]);

        $total_amount_payment = $this->totalAmountPaymentDeleteAll($request->purchase_group_id, $request->user_id_customer);
        $update_payment = PaymentModel::where('user_id', $request->user_id_customer)
            ->where('purchase_group_id', $request->purchase_group_id)
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
        $arr_purchase_customer = [];
        $final_format = [];

        // Authorize the user
        $user = $this->helper->authorizeUser($request);
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        // Get the user ID
        $user_id = $user->user_id;

        // Fetch purchases
        $purchases = PurchaseModel::where('user_id_menu', $user_id)->where('status', 'NOT PAID')->get();

        // Loop through purchases
        foreach ($purchases as $purchase) {
            $this->addPurchaseInfoToCustomerArray($arr_purchase_customer, $purchase);
        }

        foreach ($arr_purchase_customer as &$customer) {
            foreach ($customer['items'] as &$item) {
                // Get unique purchase IDs for the item
                $purchase_id = array_unique($item['array_purchase_id']);
                $item['array_purchase_id'] = array_values($purchase_id);

                // Calculate total discounted price for the item
                $totalDiscountedPrice = $this->calculateTotalDiscountedPrice($purchase_id);

                // Assign total discounted price to the item
                $item['array_discounted_price'] = $totalDiscountedPrice;

                // Assign functionsApi to the item's function
                $item['function'] = [$this->functionsApi()];
            }
        }


        $final_format[] = $arr_purchase_customer;

        // Prepare response
        $response_data = [
            'message' => 'Data retrieved successfully',
            'data' => $final_format,
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
                ->where('inventory_group_id', $purchase->inventory_group_id)
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
    private function minusStock($inventory_product_id, $inventory_group_id)
    {
        $inventory_product = InventoryProductModel::where('inventory_product_id', $inventory_product_id)
            ->where('inventory_group_id', $inventory_group_id)
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

    // CHILD getUserIdMenuCustomer
    private function addPurchaseInfoToCustomerArray(&$arr_purchase_customer, $purchase)
    {
        // Extract purchase information
        $purchase_Data = [
            'purchase_id' => $purchase->purchase_id,
            'inventory_product_id' => $purchase->inventory_product_id,
            'inventory_group_id' => $purchase->inventory_group_id,
            'purchase_group_id' => $purchase->purchase_group_id,
            'item_code' => $purchase->item_code,
            'name' => $purchase->name,
            'category' => $purchase->category,
            'design' => $purchase->design,
            'size' => $purchase->size,
            'color' => $purchase->color,
            'retail_price' => $purchase->retail_price,
            'discounted_price' => $purchase->discounted_price,
            'count' => 1,
        ];

        // Get the user ID of the customer
        $user_id_customer = $purchase->user_id_customer;

        // Check if customer already exists in the array
        if (!isset($arr_purchase_customer[$user_id_customer])) {
            $arr_purchase_customer[$user_id_customer] = [
                'payment' => [],
                'items' => [],
            ];
        }

        // Add payment information
        $arr_purchase_customer[$user_id_customer]['payment'] = PaymentModel::where('purchase_group_id', $purchase->purchase_group_id)
            ->where('user_id', $user_id_customer)
            ->get()
            ->toArray();

        // Check if the item already exists in the customer's items
        $found = false;
        foreach ($arr_purchase_customer[$user_id_customer]['items'] as &$item) {
            if ($this->purchaseMatchesItem($item, $purchase)) {
                $item['count']++;
                $item['array_purchase_id'][] = $purchase->purchase_id; // Add purchase ID to array
                $found = true;
                break;
            }
        }

        // If not found, add the item
        if (!$found) {
            $purchase_Data['array_purchase_id'] = [$purchase->purchase_id];
            $arr_purchase_customer[$user_id_customer]['items'][] = $purchase_Data;
        }
    }

    // CHILD addPurchaseInfoToCustomerArray
    private function purchaseMatchesItem($item, $purchase)
    {
        return (
            $item['inventory_product_id'] == $purchase->inventory_product_id &&
            $item['inventory_group_id'] == $purchase->inventory_group_id &&
            $item['purchase_group_id'] == $purchase->purchase_group_id &&
            $item['item_code'] == $purchase->item_code &&
            $item['name'] == $purchase->name &&
            $item['category'] == $purchase->category &&
            $item['design'] == $purchase->design &&
            $item['size'] == $purchase->size &&
            $item['color'] == $purchase->color &&
            $item['retail_price'] == $purchase->retail_price &&
            $item['discounted_price'] == $purchase->discounted_price
        );
    }

    // CHILD getUserIdMenuCustomer
    private function calculateTotalDiscountedPrice($purchase_ids)
    {
        $total_discount_price = 0;

        // Iterate through each purchase ID
        foreach ($purchase_ids as $purchase_id) {
            // Find the purchase with the given ID
            $purchase = PurchaseModel::where('purchase_id', $purchase_id)->first();

            // Add its discounted price to the total discounted price
            if ($purchase) {
                $total_discount_price += $purchase->discounted_price;
            }
        }

        return $total_discount_price;
    }

    // CHILD OF functionsApi
    private function generateFunction($prefix, $api, $payload)
    {
        return [
            'api' => $prefix . $api,
            'payload' => $payload,
        ];
    }


    // CHILD OF getUserIdMenuCustomer
    private function functionsApi()
    {
        $prefix = 'purchase/';

        $payloads = [
            'minus-qty' => ['purchase_id', 'purchase_group_id', 'inventory_product_id', 'inventory_group_id', 'user_id_customer'],
            'add-qty' => ['purchase_id', 'purchase_group_id', 'inventory_product_id', 'inventory_group_id', 'user_id_customer'],
            'delete-all-qty' => ['purchase_id', 'purchase_group_id', 'user_id_customer'],
        ];

        $functions = [];

        foreach ($payloads as $key => $payload) {
            $functions[$key] = $this->generateFunction($prefix, "{$key}", $payload);
        }

        return $functions;
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
