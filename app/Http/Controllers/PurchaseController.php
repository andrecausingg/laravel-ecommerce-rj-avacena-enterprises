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

    protected $UnsetPurchaseStorePurchaseInventory, $UnsetAddQtyPurchases, $fillAttrPurchases, $fillAttrInventoryProducts, $fillAttrPayment, $helper;

    public function __construct(Helper $helper)
    {
        $purchaseModel = new PurchaseModel();
        $inventoryProductModel = new InventoryProductModel();
        $paymentModel = new PaymentModel();

        $this->UnsetPurchaseStorePurchaseInventory = config('system.purchase.UnsetPurchaseStorePurchaseInventory');
        $this->UnsetAddQtyPurchases = config('system.purchase.UnsetAddQtyPurchase');
        $this->fillAttrPurchases = $purchaseModel->getFillableAttributes();
        $this->fillAttrInventoryProducts = $inventoryProductModel->getFillableAttributes();
        $this->fillAttrPayment = $paymentModel->getFillableAttributes();
        $this->helper = $helper;
    }

    public function store(Request $request)
    {
        $status = 'NOT PAID';
        $ctr = 0;
        $arrDataFreshCreate = [];
        $arrStoreFreshCreate = [];

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

        $inventoryProduct = InventoryProductModel::where('inventory_product_id', $request->inventory_product_id)
            ->where('inventory_group_id', $request->inventory_group_id)
            ->first();
        if (!$inventoryProduct) {
            return response()->json(['message' => 'Inventory Product ID not found'], Response::HTTP_NOT_FOUND);
        }

        if ($inventoryProduct->stock < $request->quantity) {
            return response()->json(['message' => 'Sorry, can\'t add due to insufficient stock', 'stock' => $inventoryProduct->stock], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        // Add New Item on purchase_group_id
        if ($request->purchase_group_id != '' && $request->purchase_group_id != null && $request->user_id_customer != '' && $request->user_id_customer != null) {
            do {
                foreach ($this->UnsetPurchaseStorePurchaseInventory ?? [] as $unset) {
                    // Find the key associated with the field and unset it
                    $key = array_search($unset, $this->fillAttrPurchases);
                    if ($key !== false) {
                        unset($this->fillAttrPurchases[$key]);
                    }
                }

                foreach ($this->fillAttrPurchases as $fillAttrPurchase) {
                    if ($fillAttrPurchase == 'user_id_customer') {
                        $arrStoreFreshCreate[$fillAttrPurchase] = $request->user_id_customer;
                    } else if ($fillAttrPurchase == 'purchase_group_id') {
                        $arrStoreFreshCreate[$fillAttrPurchase] = $request->purchase_group_id;
                    } else if ($fillAttrPurchase == 'user_id_menu') {
                        $arrStoreFreshCreate[$fillAttrPurchase] = $user->user_id;
                    } else if ($fillAttrPurchase == 'status') {
                        $arrStoreFreshCreate[$fillAttrPurchase] = $status;
                    } else {
                        $arrStoreFreshCreate[$fillAttrPurchase] = $inventoryProduct->$fillAttrPurchase;
                    }
                }

                // Create a new purchase record
                $createdPurchase = PurchaseModel::create($arrStoreFreshCreate);

                if (!$createdPurchase) {
                    return response()->json(
                        ['message' => 'Failed to store purchase'],
                        Response::HTTP_INTERNAL_SERVER_ERROR
                    );
                }

                // Update the purchase_id with the correct format
                $updatePurchaseId = $createdPurchase->update([
                    'purchase_id' => 'purchase_id-' . $createdPurchase->id,
                ]);
                if (!$updatePurchaseId) {
                    return response()->json(
                        ['message' => 'Failed to update purchase ID'],
                        Response::HTTP_INTERNAL_SERVER_ERROR
                    );
                }

                // Minus Stock
                $minusStock = $this->minusStock($request->inventory_product_id, $request->inventory_group_id);
                $totalAmountPayment = $this->totalAmountPayment($createdPurchase->purchase_group_id, $createdPurchase->user_id_customer);

                // Create a new payment record
                $updatePayment = PaymentModel::where('purchase_group_id', $createdPurchase->purchase_group_id)->first()->update([
                    'total_amount' => $totalAmountPayment['total_amount'],
                    'total_discounted_amount' => $totalAmountPayment['total_discounted_amount'],
                ]);

                // Check if payment record exists
                if (!$updatePayment) {
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
                    'message_stock' => $minusStock,
                ],
                Response::HTTP_OK
            );
        }
        // Fresh Create
        else {
            $groupPurchaseId = $this->generateGroupPurchaseId();
            $newCustomerId = $this->generateCustomerId();

            if ($groupPurchaseId == '') {
                return response()->json(
                    ['message' => 'Failed generate purchase I.D'],
                    Response::HTTP_INTERNAL_SERVER_ERROR
                );
            }

            if ($newCustomerId == '') {
                return response()->json(
                    ['message' => 'Failed generate costumer I.D'],
                    Response::HTTP_INTERNAL_SERVER_ERROR
                );
            }

            do {
                $arrDataFreshCreate['groupPurchaseId'] = $groupPurchaseId;
                $arrDataFreshCreate['newCustomerId'] = $newCustomerId;

                // Fresh Create start 0
                if ($ctr == 0) {

                    foreach ($this->UnsetPurchaseStorePurchaseInventory ?? [] as $unset) {
                        // Find the key associated with the field and unset it
                        $key = array_search($unset, $this->fillAttrPurchases);
                        if ($key !== false) {
                            unset($this->fillAttrPurchases[$key]);
                        }
                    }

                    foreach ($this->fillAttrPurchases as $fillAttrPurchase) {
                        if ($fillAttrPurchase == 'user_id_customer') {
                            $arrStoreFreshCreate[$fillAttrPurchase] = $arrDataFreshCreate['newCustomerId'];
                        } else if ($fillAttrPurchase == 'purchase_group_id') {
                            $arrStoreFreshCreate[$fillAttrPurchase] = $arrDataFreshCreate['groupPurchaseId'];
                        } else if ($fillAttrPurchase == 'user_id_menu') {
                            $arrStoreFreshCreate[$fillAttrPurchase] = $user->user_id;
                        } else if ($fillAttrPurchase == 'status') {
                            $arrStoreFreshCreate[$fillAttrPurchase] = $status;
                        } else {
                            $arrStoreFreshCreate[$fillAttrPurchase] = $inventoryProduct->$fillAttrPurchase;
                        }
                    }

                    // Create a new purchase record
                    $createdPurchase = PurchaseModel::create($arrStoreFreshCreate);

                    if (!$createdPurchase) {
                        return response()->json(
                            ['message' => 'Failed to store purchase'],
                            Response::HTTP_INTERNAL_SERVER_ERROR
                        );
                    }

                    // Update the purchase_id with the correct format
                    $updatePurchaseId = $createdPurchase->update([
                        'purchase_id' => 'purchase_id-' . $createdPurchase->id,
                    ]);
                    if (!$updatePurchaseId) {
                        return response()->json(
                            ['message' => 'Failed to update purchase ID'],
                            Response::HTTP_INTERNAL_SERVER_ERROR
                        );
                    }

                    // Minus Stock
                    $minusStock = $this->minusStock($request->inventory_product_id, $request->inventory_group_id);
                    $totalAmountPayment = $this->totalAmountPayment($createdPurchase->purchase_group_id, $createdPurchase->user_id_customer);

                    // Create a new payment record
                    $createdPayment = PaymentModel::create([
                        'user_id' => $createdPurchase->user_id_customer,
                        'purchase_group_id' => $createdPurchase->purchase_group_id,
                        'payment_method' => 'CASH',
                        'total_amount' => $totalAmountPayment['total_amount'],
                        'total_discounted_amount' => $totalAmountPayment['total_discounted_amount'],
                        'status' => $status,
                    ]);
                    if (!$createdPayment) {
                        return response()->json(
                            ['message' => 'Failed to store payment'],
                            Response::HTTP_INTERNAL_SERVER_ERROR
                        );
                    }

                    // Update the payment_id with the correct format
                    $updatePaymentId = $createdPayment->update([
                        'payment_id' => 'payment_id-' . $createdPayment->id,
                    ]);
                    if (!$updatePaymentId) {
                        return response()->json(
                            ['message' => 'Failed to update payment ID'],
                            Response::HTTP_INTERNAL_SERVER_ERROR
                        );
                    }
                }
                // Fresh Create but greater 0 quantity 
                else {
                    foreach ($this->UnsetPurchaseStorePurchaseInventory ?? [] as $unset) {
                        // Find the key associated with the field and unset it
                        $key = array_search($unset, $this->fillAttrPurchases);
                        if ($key !== false) {
                            unset($this->fillAttrPurchases[$key]);
                        }
                    }

                    foreach ($this->fillAttrPurchases as $fillAttrPurchase) {
                        if ($fillAttrPurchase == 'user_id_customer') {
                            $arrStoreFreshCreate[$fillAttrPurchase] = $arrDataFreshCreate['newCustomerId'];
                        } else if ($fillAttrPurchase == 'purchase_group_id') {
                            $arrStoreFreshCreate[$fillAttrPurchase] = $arrDataFreshCreate['groupPurchaseId'];
                        } else if ($fillAttrPurchase == 'user_id_menu') {
                            $arrStoreFreshCreate[$fillAttrPurchase] = $user->user_id;
                        } else if ($fillAttrPurchase == 'status') {
                            $arrStoreFreshCreate[$fillAttrPurchase] = $status;
                        } else {
                            $arrStoreFreshCreate[$fillAttrPurchase] = $inventoryProduct->$fillAttrPurchase;
                        }
                    }

                    // Create a new purchase record
                    $createdPurchase = PurchaseModel::create($arrStoreFreshCreate);

                    if (!$createdPurchase) {
                        return response()->json(
                            ['message' => 'Failed to store purchase'],
                            Response::HTTP_INTERNAL_SERVER_ERROR
                        );
                    }

                    // Update the purchase_id with the correct format
                    $updatePurchaseId = $createdPurchase->update([
                        'purchase_id' => 'purchase_id-' . $createdPurchase->id,
                    ]);
                    if (!$updatePurchaseId) {
                        return response()->json(
                            ['message' => 'Failed to update purchase ID'],
                            Response::HTTP_INTERNAL_SERVER_ERROR
                        );
                    }

                    // Minus Stock
                    $minusStock = $this->minusStock($request->inventory_product_id, $request->inventory_group_id);
                    $totalAmountPayment = $this->totalAmountPayment($createdPurchase->purchase_group_id, $createdPurchase->user_id_customer);

                    // Create a new payment record
                    $updatePayment = PaymentModel::where('purchase_group_id', $createdPurchase->purchase_group_id)->first()->update([
                        'total_amount' => $totalAmountPayment['total_amount'],
                        'total_discounted_amount' => $totalAmountPayment['total_discounted_amount'],
                    ]);

                    // Check if payment record exists
                    if (!$updatePayment) {
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
                    'message_stock' => $minusStock,
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

        $inventoryProduct = InventoryProductModel::where('inventory_product_id', $request->inventory_product_id)
            ->where('inventory_group_id', $request->inventory_group_id)
            ->first();
        if (!$inventoryProduct) {
            return response()->json(['message' => 'Inventory Product ID not found'], Response::HTTP_NOT_FOUND);
        }

        $updateStock = $inventoryProduct->update([
            'stock' => max(0, $inventoryProduct->stock + 1),
        ]);

        if (!$updateStock) {
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

        $totalAmountPayment = $this->totalAmountPayment($request->purchase_group_id, $request->user_id_customer);
        $updatePayment = PaymentModel::where('user_id', $request->user_id_customer)
            ->where('purchase_group_id', $request->purchase_group_id)
            ->first()
            ->update([
                'total_amount' => $totalAmountPayment['total_amount'],
                'total_discounted_amount' => $totalAmountPayment['total_discounted_amount'],
            ]);

        // Check if payment record exists
        if (!$updatePayment) {
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

        $inventoryProduct = InventoryProductModel::where('inventory_product_id', $request->inventory_product_id)
            ->where('inventory_group_id', $request->inventory_group_id)
            ->first();
        if (!$inventoryProduct) {
            return response()->json(['message' => 'Inventory Product ID not found'], Response::HTTP_NOT_FOUND);
        }

        $updateStock = $inventoryProduct->update([
            'stock' => max(0, $inventoryProduct->stock - 1),
        ]);

        if (!$updateStock) {
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
        $purchaseAttributes = $purchase->toArray();
        foreach ($this->UnsetAddQtyPurchases as $UnsetAddQtyPurchase) {
            unset($purchaseAttributes[$UnsetAddQtyPurchase]);
        }

        // Create a new purchase using the attributes of $purchase
        $createdPurchase = PurchaseModel::create($purchaseAttributes);

        if (!$createdPurchase) {
            return response()->json(
                [
                    'message' => 'Failed to store purchase',
                ],
                Response::HTTP_INTERNAL_SERVER_ERROR
            );
        }

        // Update the purchase_id with the correct format
        $updatePurchaseId = $createdPurchase->update([
            'purchase_id' => 'purchase_id-' . $createdPurchase->id,
        ]);
        if (!$updatePurchaseId) {
            return response()->json(
                ['message' => 'Failed to update purchase ID'],
                Response::HTTP_INTERNAL_SERVER_ERROR
            );
        }

        $totalAmountPayment = $this->totalAmountPayment($request->purchase_group_id, $request->user_id_customer);
        $updatePayment = PaymentModel::where('user_id', $request->user_id_customer)
            ->where('purchase_group_id', $request->purchase_group_id)
            ->first()
            ->update([
                'total_amount' => $totalAmountPayment['total_amount'],
                'total_discounted_amount' => $totalAmountPayment['total_discounted_amount'],
            ]);

        // Check if payment record exists
        if (!$updatePayment) {
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

        // Initialize an array to store successfully deleted purchase IDs
        $deletedPurchaseIds = [];


        foreach ($request->purchase_id as $purchase_id) {
            $purchase = PurchaseModel::where('purchase_id', $purchase_id)->first();
            if (!$purchase) {
                return response()->json(['message' => 'Purchase not found'], Response::HTTP_NOT_FOUND);
            }
            if (!$purchase->delete()) {
                return response()->json(['message' => 'Failed to delete purchase'], Response::HTTP_INTERNAL_SERVER_ERROR);
            }
            // Store the successfully deleted purchase ID
            $deletedPurchaseIds[] = $purchase_id;
        }

        // Update stock after deleting all purchases
        $inventoryProduct = InventoryProductModel::where('inventory_product_id', $purchase->inventory_product_id)
            ->where('inventory_group_id', $purchase->inventory_group_id)
            ->first();
        if (!$inventoryProduct) {
            return response()->json(['message' => 'Inventory Product ID not found'], Response::HTTP_NOT_FOUND);
        }

        $inventoryProduct->update([
            'stock' => max(0, $inventoryProduct->stock + count($deletedPurchaseIds)),
        ]);

        $totalAmountPayment = $this->totalAmountPaymentDeleteAll($request->purchase_group_id, $request->user_id_customer);
        $updatePayment = PaymentModel::where('user_id', $request->user_id_customer)
            ->where('purchase_group_id', $request->purchase_group_id)
            ->first();

        if (!$updatePayment) {
            return response()->json(['message' => 'Payment record not found'], Response::HTTP_NOT_FOUND);
        }

        $updatePayment->update([
            'total_amount' => $totalAmountPayment['total_amount'],
            'total_discounted_amount' => $totalAmountPayment['total_discounted_amount'],
        ]);

        // Check if total amount is zero and then delete the payment record
        if ($totalAmountPayment == 0) {
            if (!$updatePayment->delete()) {
                return response()->json(['message' => 'Failed to delete payment'], Response::HTTP_INTERNAL_SERVER_ERROR);
            }
        }


        // Check if payment record exists
        if (!$updatePayment) {
            return response()->json(
                ['message' => 'Failed to update total amount'],
                Response::HTTP_INTERNAL_SERVER_ERROR
            );
        }

        return response()->json(
            [
                'message' => 'Purchase and Payment records deleted successfully',
                'deleted_purchase_ids' => $deletedPurchaseIds,
            ],
            Response::HTTP_OK
        );
    }

    public function getUserIdMenuCustomer(Request $request)
    {
        // Authorize the user
        $user = $this->helper->authorizeUser($request);
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        // Get the user ID
        $user_id = $user->user_id;

        // Fetch purchases
        $purchases = PurchaseModel::where('user_id_menu', $user_id)->where('status', 'NOT PAID')->get();

        // Initialize array to store purchase information
        $arrPurchaseCustomer = [];
        $finalFormat = [];

        // Loop through purchases
        foreach ($purchases as $purchase) {
            $this->addPurchaseInfoToCustomerArray($arrPurchaseCustomer, $purchase);
        }

        foreach ($arrPurchaseCustomer as &$customer) {
            foreach ($customer['items'] as &$item) {
                // Get unique purchase IDs for the item
                $purchaseIds = array_unique($item['array_purchase_id']);
                $item['array_purchase_id'] = array_values($purchaseIds);

                // Calculate total discounted price for the item
                $totalDiscountedPrice = $this->calculateTotalDiscountedPrice($purchaseIds);

                // Assign total discounted price to the item
                $item['array_discounted_price'] = $totalDiscountedPrice;

                // Assign functionsApi to the item's function
                $item['function'] = [$this->functionsApi()];
            }
        }


        $finalFormat[] = $arrPurchaseCustomer;

        // Prepare response
        $responseData = [
            'message' => 'Data retrieved successfully',
            'data' => $finalFormat,
        ];

        return response()->json($responseData, Response::HTTP_OK);
    }

    // CHILD store
    private function generateGroupPurchaseId()
    {
        // Retrieve the last customer ID from the database
        $lastPurchase = PurchaseModel::latest()->first();

        if ($lastPurchase) {
            // Extract the numeric part of the last customer ID
            $customerId = intval(substr($lastPurchase->purchase_group_id, strrpos($lastPurchase->purchase_group_id, '-') + 1));
            // Increment the numeric part by 1
            $newPurchase = 'purchase_group_id-' . ($customerId + 1);
        } else {
            // If no existing customer IDs are found, start with 1
            $newPurchase = 'purchase_group_id-1';
        }

        return $newPurchase;
    }

    // CHILD store
    private function generateCustomerId()
    {
        // Retrieve the last customer ID from the database
        $lastCustomer = PurchaseModel::latest()->first();

        if ($lastCustomer) {
            // Extract the numeric part of the last customer ID
            $customerId = intval(substr($lastCustomer->user_id_customer, strrpos($lastCustomer->user_id_customer, '-') + 1));
            // Increment the numeric part by 1
            $newCustomerId = 'customer-' . ($customerId + 1);
        } else {
            // If no existing customer IDs are found, start with 1
            $newCustomerId = 'customer-1';
        }

        return $newCustomerId;
    }

    // CHILD store
    private function totalAmountPayment($purchaseGroupId, $customerId)
    {
        $totalAmount = 0.00;
        $totalDiscountedAmount = 0.00;
        $arrTaTdA = [];

        // Retrieve all purchases with the given purchase group ID
        $purchases = PurchaseModel::where('purchase_group_id', $purchaseGroupId)
            ->where('user_id_customer', $customerId)
            ->get();

        if ($purchases->isEmpty()) {
            // No purchases found for the given purchase group ID
            return response()->json(['message' => 'No purchases found for the given purchase group ID'], Response::HTTP_NOT_FOUND);
        }

        foreach ($purchases as $purchase) {
            $inventoryProduct = InventoryProductModel::where('inventory_product_id', $purchase->inventory_product_id)
                ->where('inventory_group_id', $purchase->inventory_group_id)
                ->first();

            if (!$inventoryProduct) {
                // Inventory product not found for the current purchase
                return response()->json(['message' => 'Inventory product not found for purchase ID ' . $purchase->id], Response::HTTP_NOT_FOUND);
            }

            // Add the price of the inventory product to the total amount
            $totalAmount += $purchase->discounted_price != 0.00 ? $purchase->discounted_price : $purchase->retail_price;
            $totalDiscountedAmount += $purchase->discounted_price;
        }

        $arrTaTdA['total_amount'] = $totalAmount;
        $arrTaTdA['total_discounted_amount'] = $totalDiscountedAmount;
        // Return the total amount
        return $arrTaTdA;
    }

    // CHILD store
    private function minusStock($inventoryProductId, $inventoryGroupId)
    {
        $inventoryProduct = InventoryProductModel::where('inventory_product_id', $inventoryProductId)
            ->where('inventory_group_id', $inventoryGroupId)
            ->first();
        if (!$inventoryProduct) {
            return response()->json(['message' => 'Inventory Product ID not found'], Response::HTTP_NOT_FOUND);
        }

        // Perform the stock deduction
        $updated = $inventoryProduct->update([
            'stock' => $inventoryProduct->stock - 1,
        ]);

        if (!$updated) {
            return response()->json(['message' => 'Failed to update new stock'], Response::HTTP_NOT_FOUND);
        }

        return response()->json(['message' => 'Stock deducted successfully'], Response::HTTP_OK);
    }

    // CHILD deleteALl
    private function totalAmountPaymentDeleteAll($purchaseGroupId, $customerId)
    {
        $totalAmount = 0.00;

        // Retrieve all purchases with the given purchase group ID
        $purchases = PurchaseModel::where('purchase_group_id', $purchaseGroupId)
            ->where('user_id_customer', $customerId)
            ->get();

        if ($purchases->isEmpty()) {
            return $totalAmount;
        }

        foreach ($purchases as $purchase) {
            $inventoryProduct = InventoryProductModel::where('inventory_product_id', $purchase->inventory_product_id)
                ->where('inventory_group_id', $purchase->inventory_group_id)
                ->first();

            if (!$inventoryProduct) {
                // Inventory product not found for the current purchase
                return response()->json(['message' => 'Inventory product not found for purchase ID ' . $purchase->id], Response::HTTP_NOT_FOUND);
            }

            // Add the price of the inventory product to the total amount
            $totalAmount += $purchase->discounted_price != 0.00 ? $purchase->discounted_price : $purchase->retail_price;
        }

        // Return the total amount
        return $totalAmount;
    }

    // CHILD getUserIdMenuCustomer
    private function addPurchaseInfoToCustomerArray(&$arrPurchaseCustomer, $purchase)
    {
        // Extract purchase information
        $purchaseData = [
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
        if (!isset($arrPurchaseCustomer[$user_id_customer])) {
            $arrPurchaseCustomer[$user_id_customer] = [
                'payment' => [],
                'items' => [],
            ];
        }

        // Add payment information
        $arrPurchaseCustomer[$user_id_customer]['payment'] = PaymentModel::where('purchase_group_id', $purchase->purchase_group_id)
            ->where('user_id', $user_id_customer)
            ->get()
            ->toArray();

        // Check if the item already exists in the customer's items
        $found = false;
        foreach ($arrPurchaseCustomer[$user_id_customer]['items'] as &$item) {
            if ($this->purchaseMatchesItem($item, $purchase)) {
                $item['count']++;
                $item['array_purchase_id'][] = $purchase->purchase_id; // Add purchase ID to array
                $found = true;
                break;
            }
        }

        // If not found, add the item
        if (!$found) {
            $purchaseData['array_purchase_id'] = [$purchase->purchase_id];
            $arrPurchaseCustomer[$user_id_customer]['items'][] = $purchaseData;
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
    private function calculateTotalDiscountedPrice($purchaseIds)
    {
        $totalDiscountedPrice = 0;

        // Iterate through each purchase ID
        foreach ($purchaseIds as $purchaseId) {
            // Find the purchase with the given ID
            $purchase = PurchaseModel::where('purchase_id', $purchaseId)->first();

            // Add its discounted price to the total discounted price
            if ($purchase) {
                $totalDiscountedPrice += $purchase->discounted_price;
            }
        }

        return $totalDiscountedPrice;
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


    // END OF GET ID MENU CUSTOMER
    // public function getUserIdMenuCustomer(Request $request)
    // {
    //     $arrPurchaseCustomer = [];
    //     $arrFinal = [];

    //     // Authorize the user
    //     $user = $this->authorizeUser($request);

    //     if (empty($user->user_id)) {
    //         return response()->json(
    //             [
    //                 'message' => 'Not authenticated user',
    //             ],
    //             Response::HTTP_INTERNAL_SERVER_ERROR
    //         );
    //     }

    //     $user_id = $user->user_id;

    //     // Fetch purchases
    //     $purchases = PurchaseModel::where('user_id_menu', $user_id)->where('status', 'NOT PAID')->get();

    //     foreach ($purchases as $purchase) {
    //         // ADD HERE
    //         $purchase_id = $purchase->purchase_id;
    //         $purchase_group_id = $purchase->purchase_group_id;
    //         $user_id_customer = $purchase->user_id_customer;
    //         $inventory_product_id = $purchase->inventory_product_id;
    //         $item_code = $purchase->item_code;
    //         $name = $purchase->name;
    //         $category = $purchase->category;
    //         $design = $purchase->design;
    //         $size = $purchase->size;
    //         $color = $purchase->color;
    //         $retail_price = $purchase->retail_price;
    //         $discounted_price = $purchase->discounted_price;


    //         // Check if customer already exists in the array
    //         if (!isset($arrPurchaseCustomer[$user_id_customer])) {
    //             $arrPurchaseCustomer[$user_id_customer] = [
    //                 'payment' => [],
    //                 'items' => [],
    //             ];
    //         }

    //         // Add payment information
    //         $arrPurchaseCustomer[$user_id_customer]['payment'] = PaymentModel::where('purchase_group_id', $purchase_group_id)
    //             ->where('user_id', $user_id_customer)
    //             ->get()
    //             ->toArray();

    //         // Check if the item already exists in the customer's items
    //         $found = false;
    //         foreach ($arrPurchaseCustomer[$user_id_customer]['items'] as &$item) {
    //             // ADD HERE
    //             if (
    //                 $item['inventory_product_id'] == $inventory_product_id && $item['purchase_group_id'] == $purchase_group_id &&
    //                 $item['item_code'] == $item_code && $item['name'] == $name &&
    //                 $item['category'] == $category && $item['design'] == $design &&
    //                 $item['size'] == $size && $item['color'] == $color &&
    //                 $item['retail_price'] == $retail_price && $item['discounted_price'] == $discounted_price
    //             ) {
    //                 $item['count']++;
    //                 $found = true;
    //                 break;
    //             }
    //         }

    //         // If not found, add the item
    //         if (!$found) {
    //             $arrPurchaseCustomer[$user_id_customer]['items'][] = [
    //                 'purchase_id' => $purchase_id,
    //                 'inventory_product_id' => $inventory_product_id,
    //                 'purchase_group_id' => $purchase_group_id,
    //                 'item_code' => $item_code,
    //                 'image' => $image,
    //                 'name' => $name,
    //                 'category' => $category,
    //                 'design' => $design,
    //                 'size' => $size,
    //                 'color' => $color,
    //                 'retail_price' => $retail_price,
    //                 'discounted_price' => $discounted_price,
    //                 'count' => 1,
    //             ];
    //         }
    //     }

    //     $arrFinal[] = $arrPurchaseCustomer;
    //     return response()->json(['message' => 'Data retrieved successfully', 'data' => $arrFinal], Response::HTTP_OK);
    // }
}
