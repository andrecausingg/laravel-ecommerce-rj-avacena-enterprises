<?php

namespace App\Http\Controllers;

use Carbon\Carbon;
use Illuminate\Support\Str;
use App\Models\PaymentModel;
use Illuminate\Http\Request;
use App\Models\PurchaseModel;
use Tymon\JWTAuth\Facades\JWTAuth;
use App\Models\InventoryProductModel;
use Illuminate\Support\Facades\Validator;
use Symfony\Component\HttpFoundation\Response;

class PurchaseController extends Controller
{

    protected $fillableAttributes;

    public function __construct()
    {
        // Get the Attribute
        $logsModel = new PurchaseModel();
        $this->fillableAttributes = $logsModel->getFillableAttributes();
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
     * Store a newly created resource in storage.
     */
    public function store(Request $request)
    {
        $statusPayment = 'NOT PAID';
        $statusPurchase = 'PENDING';
        $ctr = 0;
        $arrLogs = [];
        $arrDataFreshCreate = [];

        // Authorize the user
        $user = $this->authorizeUser($request);

        if (empty($user->user_id)) {
            return response()->json(
                [
                    'message' => 'Not authenticated user',
                ],
                Response::HTTP_INTERNAL_SERVER_ERROR
            );
        }

        // Validation rules for each item in the array
        $validator = Validator::make($request->all(), [
            'inventory_product_id' => 'required|string',
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

        $inventoryProduct = InventoryProductModel::where('inventory_product_id', $request->inventory_product_id)->first();
        if (!$inventoryProduct) {
            return response()->json(['message' => 'Inventory Product ID not found'], Response::HTTP_NOT_FOUND);
        }

        if ($inventoryProduct->stock < $request->quantity) {
            return response()->json(['message' => 'Sorry, can\'t add due to insufficient stock', 'stock' => $inventoryProduct->stock], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        // Add New Item
        if ($request->purchase_group_id != '' && $request->purchase_group_id != null && $request->user_id_customer != '' && $request->user_id_customer != null) {
            do {
                $createdPurchase = PurchaseModel::create([
                    'inventory_product_id' => $request->inventory_product_id,
                    'purchase_group_id' => $request->purchase_group_id,
                    'user_id_menu' => $user->user_id,
                    'user_id_customer' => $request->user_id_customer,
                    'status' => $statusPurchase,
                ]);
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
                $minusStock = $this->minusStock($request->inventory_product_id);
                $totalAmountPayment = $this->totalAmountPayment($createdPurchase->purchase_group_id);

                // Create a new payment record
                $payment = PaymentModel::where('purchase_group_id', $request->purchase_group_id)->first();
                if (!$payment) {
                    return response()->json(
                        ['message' => 'Purchase group I.D not found'],
                        Response::HTTP_INTERNAL_SERVER_ERROR
                    );
                }

                $updatePayment = $payment->update([
                    'total_amount' => $totalAmountPayment,
                ]);

                if (!$updatePayment) {
                    return response()->json(
                        ['message' => 'Failed to update total amount'],
                        Response::HTTP_INTERNAL_SERVER_ERROR
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

                // Fresh Create
                if ($ctr == 0) {
                    // Create a new purchase record
                    $createdPurchase = PurchaseModel::create([
                        'inventory_product_id' => $request->inventory_product_id,
                        'purchase_group_id' => $groupPurchaseId,
                        'user_id_menu' => $user->user_id,
                        'user_id_customer' => $newCustomerId,
                        'status' => $statusPurchase,
                    ]);
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
                    $minusStock = $this->minusStock($request->inventory_product_id);
                    $totalAmountPayment = $this->totalAmountPayment($createdPurchase->purchase_group_id);

                    // Create a new payment record
                    $createdPayment = PaymentModel::create([
                        'user_id' => $createdPurchase->user_id_customer,
                        'purchase_group_id' => $createdPurchase->purchase_group_id,
                        'payment_method' => 'CASH',
                        'total_amount' => $totalAmountPayment,
                        'status' => $statusPayment,
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
                // Fresh Create but greater 1 quantity 
                else {
                    $createdPurchase = PurchaseModel::create([
                        'inventory_product_id' => $request->inventory_product_id,
                        'purchase_group_id' => $arrDataFreshCreate['groupPurchaseId'],
                        'user_id_menu' => $user->user_id,
                        'user_id_customer' => $arrDataFreshCreate['newCustomerId'],
                        'status' => $statusPurchase,
                    ]);
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
                    $minusStock = $this->minusStock($request->inventory_product_id);
                    $totalAmountPayment = $this->totalAmountPayment($createdPurchase->purchase_group_id);

                    // Create a new payment record
                    $payment = PaymentModel::where('purchase_group_id', $arrDataFreshCreate['groupPurchaseId'])->first();
                    if (!$payment) {
                        return response()->json(
                            ['message' => 'Purchase group I.D not found'],
                            Response::HTTP_INTERNAL_SERVER_ERROR
                        );
                    }

                    $updatePayment = $payment->update([
                        'total_amount' => $totalAmountPayment,
                    ]);

                    if (!$updatePayment) {
                        return response()->json(
                            ['message' => 'Failed to update total amount'],
                            Response::HTTP_INTERNAL_SERVER_ERROR
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


    public function authorizeUser($request)
    {
        try {
            // Authenticate the user with the provided token
            $user = JWTAuth::parseToken()->authenticate();
            if (!$user) {
                return response()->json(['error' => 'User not found'], Response::HTTP_UNAUTHORIZED);
            }

            // Get the bearer token from the headers
            $bearerToken = $request->bearerToken();
            if (!$bearerToken || $user->session_token !== $bearerToken || $user->session_expire_at < Carbon::now()) {
                return response()->json(['error' => 'Invalid token'], Response::HTTP_UNAUTHORIZED);
            }

            return $user;
        } catch (\Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {
            return response()->json(['error' => 'Token expired'], Response::HTTP_UNAUTHORIZED);
        } catch (\Tymon\JWTAuth\Exceptions\TokenInvalidException $e) {
            return response()->json(['error' => 'Invalid token'], Response::HTTP_UNAUTHORIZED);
        } catch (\Tymon\JWTAuth\Exceptions\JWTException $e) {
            return response()->json(['error' => 'Failed to authenticate'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    public function generateGroupPurchaseId()
    {
        do {
            $uuid = Str::uuid();
        } while (PurchaseModel::where('purchase_group_id', $uuid)->exists());

        return $uuid;
    }

    public function generateCustomerId()
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

    public function totalAmountPayment($purchaseGroupId)
    {
        $totalAmount = 0.00;

        // Retrieve all purchases with the given purchase group ID
        $purchases = PurchaseModel::where('purchase_group_id', $purchaseGroupId)->get();

        if ($purchases->isEmpty()) {
            // No purchases found for the given purchase group ID
            return response()->json(['message' => 'No purchases found for the given purchase group ID'], Response::HTTP_NOT_FOUND);
        }

        foreach ($purchases as $purchase) {
            $inventoryProduct = InventoryProductModel::where('inventory_product_id', $purchase->inventory_product_id)->first();

            if (!$inventoryProduct) {
                // Inventory product not found for the current purchase
                return response()->json(['message' => 'Inventory product not found for purchase ID ' . $purchase->id], Response::HTTP_NOT_FOUND);
            }

            // Add the price of the inventory product to the total amount
            $totalAmount += $inventoryProduct->discounted_price != 0.00 ? $inventoryProduct->discounted_price : $inventoryProduct->retail_price;
        }

        // Return the total amount
        return $totalAmount;
    }

    public function minusStock($inventoryProductId)
    {
        $inventoryProduct = InventoryProductModel::where('inventory_product_id', $inventoryProductId)->first();
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

    public function freshCreate()
    {
    }
}
