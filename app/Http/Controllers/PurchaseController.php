<?php

namespace App\Http\Controllers;

use Carbon\Carbon;
use Ramsey\Uuid\Uuid;
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

    protected $UnsetPurchaseStorePurchaseInventory, $fillAttrPurchases, $fillAttrInventoryProducts, $fillAttrPayment, $UnsetDetailsInventoryPlaceOrder;

    public function __construct()
    {
        $purchaseModel = new PurchaseModel();
        $inventoryProductModel = new InventoryProductModel();
        $paymentModel = new PaymentModel();

        $this->UnsetPurchaseStorePurchaseInventory = config('purchase.UnsetPurchaseStorePurchaseInventory');
        $this->UnsetDetailsInventoryPlaceOrder = config('purchase.UnsetDetailsInventoryPlaceOrder');
        $this->fillAttrPurchases = $purchaseModel->getFillableAttributes();
        $this->fillAttrInventoryProducts = $inventoryProductModel->getFillableAttributes();
        $this->fillAttrPayment = $paymentModel->getFillableAttributes();
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
        $status = 'NOT PAID';
        $ctr = 0;
        $arrDataFreshCreate = [];
        $arrStoreFreshCreate = [];

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

                // dd($groupPurchaseId);

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
                $minusStock = $this->minusStock($request->inventory_product_id);
                $totalAmountPayment = $this->totalAmountPayment($createdPurchase->purchase_group_id);

                // Create a new payment record
                $updatePayment = PaymentModel::where('purchase_group_id', $createdPurchase->purchase_group_id)->first()->update([
                    'total_amount' => $totalAmountPayment,
                ]);

                // Check if payment record exists
                if (!$updatePayment) {
                    return response()->json(
                        ['message' => 'Payment record not found'],
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

                // Fresh Create
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

                    // dd($groupPurchaseId);

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
                    $minusStock = $this->minusStock($request->inventory_product_id);
                    $totalAmountPayment = $this->totalAmountPayment($createdPurchase->purchase_group_id);

                    // Create a new payment record
                    $createdPayment = PaymentModel::create([
                        'user_id' => $createdPurchase->user_id_customer,
                        'purchase_group_id' => $createdPurchase->purchase_group_id,
                        'payment_method' => 'CASH',
                        'total_amount' => $totalAmountPayment,
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
                // Fresh Create but greater 1 quantity 
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

                    // dd($groupPurchaseId);

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
                    $minusStock = $this->minusStock($request->inventory_product_id);
                    $totalAmountPayment = $this->totalAmountPayment($createdPurchase->purchase_group_id);

                    // Create a new payment record
                    $updatePayment = PaymentModel::where('purchase_group_id', $createdPurchase->purchase_group_id)->first()->update([
                        'total_amount' => $totalAmountPayment,
                    ]);

                    // Check if payment record exists
                    if (!$updatePayment) {
                        return response()->json(
                            ['message' => 'Payment record not found'],
                            Response::HTTP_NOT_FOUND
                        );
                    }
                }

                $ctr++;
            } while ($ctr < $request->quantity);


            return response()->json(
                [
                    'message' => 'Purchase and Payment records stored successfully',
                    // 'message_stock' => $minusStock,
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

    public function getUserIdMenuCustomer(Request $request)
    {
        $arrPurchaseCustomer = [];
        $arrFinal = [];

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

        $user_id = $user->user_id;

        // Fetch purchases
        $purchases = PurchaseModel::where('user_id_menu', $user_id)->get();

        foreach ($purchases as $purchase) {
            $group_id = $purchase->purchase_group_id;
            $customer_id = $purchase->user_id_customer;
            $product_id = $purchase->inventory_product_id;

            // Check if customer already exists in the array
            if (!isset($arrPurchaseCustomer[$customer_id])) {
                $arrPurchaseCustomer[$customer_id] = [
                    'payment' => [],
                    'items' => [],
                ];
            }

            // Add payment information
            $arrPurchaseCustomer[$customer_id]['payment'] = PaymentModel::where('purchase_group_id', $group_id)
                ->where('user_id', $customer_id)
                ->get()
                ->toArray();

            // Check if the item already exists in the customer's items
            $found = false;
            foreach ($arrPurchaseCustomer[$customer_id]['items'] as &$item) {
                if ($item['product_id'] == $product_id && $item['group_id'] == $group_id) {
                    $item['count']++;
                    $found = true;
                    break;
                }
            }

            // If not found, add the item
            if (!$found) {
                $arrPurchaseCustomer[$customer_id]['items'][] = [
                    'product_id' => $product_id,
                    'group_id' => $group_id,
                    'count' => 1,
                ];
            }
        }

        // Remove unwanted attributes from the fillable list
        $attributesToRemove = ['retail_price', 'discounted_price', 'unit_supplier_price', 'stock', 'created_at', 'updated_at'];
        $this->fillAttrInventoryProducts = array_diff($this->fillAttrInventoryProducts, $attributesToRemove);

        // Fetch additional information from InventoryProductModel dynamically and nest it under 'detail'
        foreach ($arrPurchaseCustomer as &$customer) {
            foreach ($customer['items'] as &$purchase) {
                $product = InventoryProductModel::where('inventory_product_id', $purchase['product_id'])->first();
                if ($product) {
                    $purchase['detail'] = [];
                    foreach ($this->fillAttrInventoryProducts as $attribute) {
                        $purchase['detail'][$attribute] = $product->$attribute;
                    }
                }
            }
        }

        $arrFinal[] = $arrPurchaseCustomer;
        return response()->json(['message' => 'Data retrieved successfully', 'data' => $arrFinal], Response::HTTP_OK);
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

        // do {
        //     $uuid = Str::uuid();
        // } while (PurchaseModel::where('purchase_group_id', $uuid)->exists());

        // return $uuid;

        // do {
        //     $uuid = Uuid::uuid4()->toString();
        // } while (PurchaseModel::where('purchase_group_id', $uuid)->exists());

        // return $uuid;
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
}
