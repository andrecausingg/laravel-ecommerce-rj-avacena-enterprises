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

    protected $UnsetPurchaseStorePurchaseInventory, $fillAttrPurchases, $fillAttrInventoryProducts, $fillAttrPayment;

    public function __construct()
    {
        $purchaseModel = new PurchaseModel();
        $inventoryProductModel = new InventoryProductModel();
        $paymentModel = new PaymentModel();

        $this->UnsetPurchaseStorePurchaseInventory = config('purchase.UnsetPurchaseStorePurchaseInventory');
        $this->fillAttrPurchases = $purchaseModel->getFillableAttributes();
        $this->fillAttrInventoryProducts = $inventoryProductModel->getFillableAttributes();
        $this->fillAttrPayment = $paymentModel->getFillableAttributes();
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
                    'total_amount' => $totalAmountPayment,
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
                    $minusStock = $this->minusStock($request->inventory_product_id, $request->inventory_group_id);
                    $totalAmountPayment = $this->totalAmountPayment($createdPurchase->purchase_group_id, $createdPurchase->user_id_customer);

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
                    $minusStock = $this->minusStock($request->inventory_product_id, $request->inventory_group_id);
                    $totalAmountPayment = $this->totalAmountPayment($createdPurchase->purchase_group_id, $createdPurchase->user_id_customer);

                    // Create a new payment record
                    $updatePayment = PaymentModel::where('purchase_group_id', $createdPurchase->purchase_group_id)->first()->update([
                        'total_amount' => $totalAmountPayment,
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

        // Add New Item on purchase_group_id
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
                    'message' => 'Failed to minus quantity',
                ],
                Response::HTTP_INTERNAL_SERVER_ERROR
            );
        }

        $purchase->softDelete();

        $totalAmountPayment = $this->totalAmountPayment($request->purchase_group_id, $request->user_id_customer);
        $updatePayment = PaymentModel::where('user_id', $request->user_id_customer)
            ->where('purchase_group_id', $request->purchase_group_id)
            ->first()
            ->update([
                'total_amount' => $totalAmountPayment,
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
            ],
            Response::HTTP_OK
        );
    }

    public function getUserIdMenuCustomer(Request $request)
    {
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

        $finalFormat[] = $arrPurchaseCustomer;

        // Prepare response
        $responseData = [
            'message' => 'Data retrieved successfully',
            'data' => $finalFormat,
        ];

        return response()->json($responseData, Response::HTTP_OK);
    }

    // GLOBAL Auth
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

    // CHILD store
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
    }

    // CHILD store
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

    // CHILD store
    public function totalAmountPayment($purchaseGroupId, $customerId)
    {
        $totalAmount = 0.00;

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
        }

        // Return the total amount
        return $totalAmount;
    }

    // CHILD store
    public function minusStock($inventoryProductId, $inventoryGroupId)
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

    // CHILD getUserIdMenuCustomer
    private function addPurchaseInfoToCustomerArray(&$arrPurchaseCustomer, $purchase)
    {
        // Extract purchase information
        $purchaseData = [
            'purchase_id' => $purchase->purchase_id,
            'inventory_product_id' => $purchase->inventory_product_id,
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
                $found = true;
                break;
            }
        }

        // If not found, add the item
        if (!$found) {
            $arrPurchaseCustomer[$user_id_customer]['items'][] = $purchaseData;
        }
    }

    // CHILD addPurchaseInfoToCustomerArray
    private function purchaseMatchesItem($item, $purchase)
    {
        return (
            $item['inventory_product_id'] == $purchase->inventory_product_id &&
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
