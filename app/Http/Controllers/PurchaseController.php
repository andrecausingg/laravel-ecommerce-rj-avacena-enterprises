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
        $status = 'NEW';
        $arrLogs = [];

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
            'user_id_costumer' => 'nullable',
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

        if ($request->purchase_group_id != '' && $request->user_id_costumer != '') {
            $inventoryProduct = InventoryProductModel::where('inventory_product_id', $request->inventory_product_id)->first();
            if (!$inventoryProduct) {
                return response()->json(['message' => 'Inventory Product ID not found'], Response::HTTP_NOT_FOUND);
            }

            // Create a new record
            $created = PurchaseModel::create([
                'inventory_product_id' => $request->inventory_product_id,
                'purchase_group_id' => $request->purchase_group_id,
                'user_id_costumer' => $request->user_id_costumer,
                'user_id_menu' => $user,
                'status' => "NEW",
            ]);

            // if ($created) {
            //     $arrLogs['fields_purchase'] = $created;
            //     $arrLogs['fields_inventory_product'] = $inventoryProduct;
            // }
        } else {
            $inventoryProduct = InventoryProductModel::where('inventory_product_id', $request->inventory_product_id)->first();
            if (!$inventoryProduct) {
                return response()->json(['message' => 'Inventory Product ID not found'], Response::HTTP_NOT_FOUND);
            }

            $groupPurchaseId = $this->generateGroupPurchaseId();
            $newCustomerId = $this->generateCustomerId();

            if ($groupPurchaseId != '' && $newCustomerId != '') {
                // Create a new record
                $createdPurchase = PurchaseModel::create([
                    'inventory_product_id' => $request->inventory_product_id,
                    'purchase_group_id' => $groupPurchaseId,
                    'user_id_menu' => $user->user_id,
                    'user_id_costumer' => $newCustomerId,
                    'status' => "NEW",
                ]);
                if (!$createdPurchase) {
                    return response()->json(
                        [
                            'message' => 'Failed to store purchase',
                        ],
                        Response::HTTP_INTERNAL_SERVER_ERROR
                    );
                }

                $updatePurchaseId = $createdPurchase->update([
                    $createdPurchase->purchase_id => 'purchase_id' . $createdPurchase->id,
                ]);

                if (!$updatePurchaseId) {
                    return response()->json(
                        [
                            'message' => 'Failed to update purchase I.D',
                        ],
                        Response::HTTP_INTERNAL_SERVER_ERROR
                    );
                }

                $updatedPurchase = PurchaseModel::find($createdPurchase->id);
                $totalAmountPayment = $this->totalAmountPayment($updatedPurchase->purchase_group_id);

                // Create a new record
                $createdPayment = PaymentModel::create([
                    'user_id' => $updatedPurchase->user_id_costumer,
                    'purchase_group_id' => $updatedPurchase->purchase_group_id,
                    'payment_method' => 'CASH',
                    'total_amount' => $totalAmountPayment,
                    'status' => "NOT PAID",
                ]);
                if (!$createdPayment) {
                    return response()->json(
                        [
                            'message' => 'Failed to store payment',
                        ],
                        Response::HTTP_INTERNAL_SERVER_ERROR
                    );
                }


                $arrLogs['fields_purchase'] = $createdPurchase;
                $arrLogs['fields_inventory_product'] = $inventoryProduct;
                $arrLogs['fieds_payment'] = $inventoryProduct;
            }
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
            $customerId = intval(substr($lastCustomer->user_id_costumer, strrpos($lastCustomer->user_id_costumer, '-') + 1));
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
    
    
}
