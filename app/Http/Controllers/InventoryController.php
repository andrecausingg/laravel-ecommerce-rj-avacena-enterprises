<?php

namespace App\Http\Controllers;

use App\Models\LogsModel;
use Illuminate\Support\Str;
use Illuminate\Http\Request;
use App\Models\InventoryModel;
use Illuminate\Support\Carbon;
use Tymon\JWTAuth\Facades\JWTAuth;
use App\Models\InventoryProductModel;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\Validator;
use Symfony\Component\HttpFoundation\Response;

class InventoryController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index()
    {
        //
    }

    public function storeParent(Request $request)
    {
        // Authorize the user
        $user = $this->authorizeUser($request);

        if (empty($user->id_hash)) {
            return response()->json(
                [
                    'message' => 'Not authenticated user',
                ],
                Response::HTTP_INTERNAL_SERVER_ERROR
            );
        }

        // Check if 'items' key exists in the request
        if (!$request->has('items')) {
            return response()->json(
                [
                    'message' => 'Missing items in the request',
                ],
                Response::HTTP_INTERNAL_SERVER_ERROR
            );
        }

        // Validation rules for each item in the array
        $validator = Validator::make($request->all(), [
            'items.*.name' => 'required|string|max:255',
            'items.*.category' => 'required|string|max:255',
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

        // Initialize an array to store all created items
        $createdItems = [];

        foreach ($request['items'] as $productUserInput) {
            $created = InventoryModel::create([
                'name' => $productUserInput['name'],
                'category' => $productUserInput['category'],
            ]);

            if ($created) {
                // Retrieve the last inserted ID from the created record
                $lastInsertedId = $created->id;

                // Update the inventory_id based on the retrieved ID
                $created->update([
                    'group_id' => "invgro#" . $lastInsertedId,
                    'inventory_id' => 'inv#' . $lastInsertedId,
                ]);

                $createdItems[] = $created; // Add the created item to the array
            } else {
                return response()->json(
                    [
                        'message' => 'Failed to store Inventory Parents',
                    ],
                    Response::HTTP_INTERNAL_SERVER_ERROR
                );
            }
        }

        $this->storeInventoryParentLogs($request, $user->id_hash, $createdItems);

        return response()->json(
            [
                'message' => 'Inventory records parent store successfully',
            ],
            Response::HTTP_OK
        );
    }

    public function editParent(string $id){
        
    }

    /**
     * Store a newly created resource in storage.
     */
    public function storeProduct(Request $request)
    {
        // Authorize the user
        $user = $this->authorizeUser($request);

        if (empty($user->id_hash)) {
            return response()->json(
                [
                    'message' => 'Not authenticated user',
                ],
                Response::HTTP_INTERNAL_SERVER_ERROR
            );
        }

        // Check if 'items' key exists in the request
        if (!$request->has('items')) {
            return response()->json(
                [
                    'message' => 'Missing items in the request',
                ],
                Response::HTTP_INTERNAL_SERVER_ERROR
            );
        }

        // Validation rules for each item in the array
        $validator = Validator::make($request->all(), [
            'items.*.inventory_group_id' => 'required|string|max:500',
            'items.*.item_code' => 'required|string|max:255',
            'items.*.image' => 'nullable|image|mimes:jpeg,png,jpg,gif|max:2048',
            'items.*.description' => 'nullable',
            'items.*.is_refund' => 'nullable',
            'items.*.name' => 'required|string|max:500',
            'items.*.category' => 'required|string|max:500',
            'items.*.retail_price' => 'required|numeric',
            'items.*.discounted_price' => 'nullable|numeric',
            'items.*.stock' => 'required|numeric',
            'items.*.supplier_name' => 'nullable',
            'items.*.unit_supplier_price' => 'nullable|numeric',
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

        // Generate a unique group_id using Str::uuid()
        do {
            $uuid = Str::uuid();
        } while (InventoryModel::where('group_id', $uuid)->exists());

        // Initialize an array to store all created items
        $createdItems = [];

        foreach ($request['items'] as $productUserInput) {
            // Handle image upload and update
            if ($productUserInput['image'] && $productUserInput['image']->hasFile('image')) {
                $image = $productUserInput['image'];
                $imageActualExt = $image->getClientOriginalExtension();

                // Generate File Name
                $filename = Str::uuid() . "_" . time() . "_" . mt_rand() . "_" . Str::uuid() . "." . $imageActualExt;

                // Save on Storage
                Storage::disk('public')->put($filename, file_get_contents($image));
            }

            $created = InventoryProductModel::create([
                'inventory_group_id' => $productUserInput['inventory_group_id'],
                'item_code' => $productUserInput['item_code'],
                'image' => $filename ?? null,
                'name' => $productUserInput['name'],
                'description' => $productUserInput['description'],
                'is_refund' => $productUserInput['is_refund'],
                'category' => $productUserInput['category'],
                'retail_price' => $productUserInput['retail_price'],
                'discounted_price' => $productUserInput['discounted_price'],
                'stock' => $productUserInput['stock'],
                'supplier_name' => $productUserInput['supplier_name'],
                'unit_supplier_price' => $productUserInput['unit_supplier_price'],
            ]);

            if ($created) {
                // Retrieve the last inserted ID from the created record
                $lastInsertedId = $created->id;

                // Update the inventory_id based on the retrieved ID
                $created->update([
                    'product_id' => 'product#' . $lastInsertedId,
                ]);

                $createdItems[] = $created; // Add the created item to the array
            } else {
                return response()->json(
                    [
                        'message' => 'Failed to store Inventory Parents',
                    ],
                    Response::HTTP_INTERNAL_SERVER_ERROR
                );
            }
        }

        $this->storeInventoryProductLogs($request, $user->id_hash, $createdItems);

        return response()->json(
            [
                'message' => 'Inventory records parent store successfully',
            ],
            Response::HTTP_OK
        );
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

    // GLOBAL FUNCTIONS
    // Code to check if authenticate users
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


    // LOGS
    public function storeInventoryParentLogs(Request $request, $idHash, $storeData)
    {
        // Get Device Information
        $userAgent = $request->header('User-Agent');

        // Define the fields to include in the logs
        $fieldsToInclude = [
            'inventory_id', 'group_id', 'name', 'category',
        ];

        // Loop through each created item and add them to data
        $data = [];
        foreach ($storeData as $item) {
            $itemData = [];
            foreach ($fieldsToInclude as $field) {
                $itemData[$field] = $item->$field;
            }
            $data[] = $itemData;
        }

        $details = json_encode($data, JSON_PRETTY_PRINT);

        // Create LogsModel entry
        $logEntry = LogsModel::create([
            'user_id_hash' => $idHash,
            'ip_address' => $request->ip(),
            'user_action' => 'STORE INVENTORY PARENT',
            'user_device' => $userAgent,
            'details' => $details,
        ]);

        if (!$logEntry) {
            return response()->json(['message' => 'Failed to store logs for store inventory parent'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    public function storeInventoryProductLogs(Request $request, $idHash, $storeData)
    {
        // Get Device Information
        $userAgent = $request->header('User-Agent');

        // Define the fields to include in the logs
        $fieldsToInclude = [
            'inventory_group_id', 'item_code', 'image', 'description', 'is_refund', 'name',
            'category', 'retail_price', 'discounted_price', 'stock',
            'supplier_name', 'unit_supplier_price'
        ];

        // Loop through each created item and add them to data
        $data = [];
        foreach ($storeData as $item) {
            $itemData = [];
            foreach ($fieldsToInclude as $field) {
                $itemData[$field] = $item->$field;
            }
            $data[] = $itemData;
        }

        $details = json_encode($data, JSON_PRETTY_PRINT);

        // Create LogsModel entry
        $logEntry = LogsModel::create([
            'user_id_hash' => $idHash,
            'ip_address' => $request->ip(),
            'user_action' => 'STORE INVENTORY PRODUCT',
            'user_device' => $userAgent,
            'details' => $details,
        ]);

        if (!$logEntry) {
            return response()->json(['message' => 'Failed to store logs for store inventory product'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }
}
