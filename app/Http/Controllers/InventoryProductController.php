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

class InventoryProductController extends Controller
{

    protected $fillableAttributes, $unsets, $userInputFields;

    public function __construct()
    {
        $this->unsets = config('a-global.Unset-Timestamp');

        $InventoryProductModel = new InventoryProductModel();
        $this->fillableAttributes = $InventoryProductModel->getFillableAttributes();
    }

    /**
     * Display a listing of the resource.
     */
    public function index(Request $request)
    {
        // Authorize the user
        $user = $this->authorizeUser($request);

        // Check if authenticated user
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        $inventoryProduct = InventoryProductModel::get();

        return response()->json(
            [
                'message' => 'Successfully Retrieve Data',
                'result' => $inventoryProduct
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
     * Store a newly created resource in storage.
     */
    public function store(Request $request)
    {
        // Initialize an array to store all created items
        $createdItems = [];

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
            'items.*.name' => 'required|string|max:500|unique:inventory_product_tbl,name',
            'items.*.category' => 'required|string|max:500',
            'items.*.retail_price' => 'required|numeric',
            'items.*.discounted_price' => 'nullable|numeric',
            'items.*.stock' => 'required|numeric',
            'items.*.supplier_name' => 'nullable',
            'items.*.design' => 'nullable',
            'items.*.size' => 'nullable',
            'items.*.color' => 'nullable',
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

        foreach ($request['items'] as $productUserInput) {
            // Retrieve the inventory record
            $inventory = InventoryModel::where('group_id', $productUserInput['inventory_group_id'])->first();

            // Check if inventory record exists
            if (!$inventory) {
                return response()->json(['message' => 'Parent inventory I.D not found'], Response::HTTP_NOT_FOUND);
            }

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
                    'inventory_product_id' => 'inv_prod_id-' . $lastInsertedId,
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

        $logResult = $this->storeLogs($request, $user->user_id, $createdItems);

        return response()->json(
            [
                'message' => 'Inventory records parent store successfully',
                'log_message' => $logResult
            ],
            Response::HTTP_OK
        );
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
    public function update(Request $request)
    {

        $changesForLogs = [];
        $changesForLogsItem = [];

        // Authorize the user
        $user = $this->authorizeUser($request);
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        // Check if 'items' key exists in the request
        if (!$request->has('items') || empty($request['items'])) {
            return response()->json(['message' => 'Missing or empty items in the request'], Response::HTTP_BAD_REQUEST);
        }


        foreach ($this->unsets as $unset) {
            // Find the key associated with the field and unset it
            $key = array_search($unset, $this->fillableAttributes);
            if ($key !== false) {
                unset($this->fillableAttributes[$key]);
            }
        }

        foreach ($request['items'] as $productUserInput) {
            // Retrieve the inventory record
            $inventory = InventoryProductModel::where('inventory_product_id', $productUserInput['inventory_product_id'])->first();

            // Check if inventory record exists
            if (!$inventory) {
                return response()->json(['message' => 'Data not found'], Response::HTTP_NOT_FOUND);
            }

            // Handle image upload and update
            if ($request->hasFile('items.*.image')) {
                $image = $productUserInput['image'];
                $image->validate([
                    'image' => 'image|mimes:jpeg,png,jpg,gif|max:2048',
                ]);
                $filename = Str::uuid() . "_" . time() . "_" . mt_rand() . "_" . Str::uuid() . "." . $image->getClientOriginalExtension();
                Storage::disk('public')->put($filename, file_get_contents($image));
                $productUserInput['image'] = $filename;
            }

            foreach ($this->fillableAttributes as $fillableAttribute) {
                $existingValue = $inventory->$fillableAttribute ?? null;
                $newValue = $productUserInput[$fillableAttribute] ?? null;

                // Check if the value has changed
                if ($existingValue !== $newValue) {
                    $changesForLogsItem[$fillableAttribute] = [
                        'old' => $existingValue,
                        'new' => $newValue,
                    ];
                }
            }

            // Log the changes for the current item
            $changesForLogs[] = [
                'inventory_product_id' => $productUserInput['inventory_product_id'],
                'inventory_group_id' => $productUserInput['inventory_group_id'],
                'fields' => $changesForLogsItem,
            ];

            // Update the inventory info
            foreach ($this->fillableAttributes as $fillableAttribute) {
                $inventory->$fillableAttribute = $productUserInput[$fillableAttribute];
            }

            // Save the updated inventory
            if (!$inventory->save()) {
                return response()->json(['message' => 'Failed to update inventory'], Response::HTTP_INTERNAL_SERVER_ERROR);
            }
        }

        foreach ($changesForLogs as $item) {
            if (array_key_exists('fields', $item) && is_array($item['fields']) && empty($item['fields'])) {
                return response()->json(['message' => 'No changes have been made'], Response::HTTP_UNPROCESSABLE_ENTITY);
            }
        }

        // Log all changes
        $resultLogs = $this->updateLogs($request, $user->user_id, $changesForLogs);

        return response()->json([
            'message' => 'All inventory child records updated successfully',
            'log_message' => $resultLogs
        ], Response::HTTP_OK);
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

    public function storeLogs($request, $userId, $logDetails)
    {
        $arr = [];
        $arr['fields'] = $logDetails;

        // Get Device Information
        $userAgent = $request->header('User-Agent');

        // Create LogsModel entry
        $log = LogsModel::create([
            'user_id' => $userId,
            'ip_address' => $request->ip(),
            'user_action' => 'STORE INVENTORY CHILD',
            'user_device' => $userAgent,
            'details' => json_encode($arr, JSON_PRETTY_PRINT),
        ]);

        if ($log) {
            $log->update([
                'log_id' => 'log_id-'  . $log->id,
            ]);
        } else {
            return response()->json(['message' => 'Failed to store logs for store inventory child'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        return response()->json(['message' => 'Successfully stored inventory child'], Response::HTTP_OK);
    }

    public function updateLogs($request, $userId, $logDetails)
    {
        $arr = [];
        $arr['fields'] = $logDetails;

        // Get Device Information
        $userAgent = $request->header('User-Agent');

        // Create LogsModel entry
        $log = LogsModel::create([
            'user_id' => $userId,
            'ip_address' => $request->ip(),
            'user_action' => 'UPDATE INVENTORY CHILD',
            'user_device' => $userAgent,
            'details' => json_encode($arr, JSON_PRETTY_PRINT),
        ]);

        if ($log) {
            $log->update([
                'log_id' => 'log_id-'  . $log->id,
            ]);
        } else {
            return response()->json(['message' => 'Failed to update logs for update inventory child'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        return response()->json(['message' => 'Successfully update inventory child'], Response::HTTP_OK);
    }
}
