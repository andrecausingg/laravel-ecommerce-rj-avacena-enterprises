<?php

namespace App\Http\Controllers;

use App\Models\LogsModel;
use Illuminate\Support\Str;
use App\Models\HistoryModel;
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
                    'group_id' => "invgro-" . $lastInsertedId,
                    'inventory_id' => 'inv-' . $lastInsertedId,
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

        $this->storeLogs($request, $user->id_hash, $createdItems);

        return response()->json(
            [
                'message' => 'Inventory records parent store successfully',
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
    public function edit(Request $request, string $id)
    {
        // Authorize the user
        $user = $this->authorizeUser($request);

        if (empty($user->id_hash)) {
            return response()->json(
                [
                    'message' => 'Not authenticated user',
                ],
                Response::HTTP_UNAUTHORIZED
            );
        }

        $inventory = InventoryModel::where('inventory_id', $id)->first();
        if (!$inventory) {
            return response()->json(
                [
                    'message' => 'Data not found',
                ],
                Response::HTTP_NOT_FOUND
            );
        }

        return response()->json(
            [
                "message" => "Successfully Retrieve Data",
                'result' => $inventory,
            ],
            Response::HTTP_OK
        );
    }


    /**
     * Update the specified resource in storage.
     */
    public function update(Request $request)
    {
        // Authorize the user
        $user = $this->authorizeUser($request);

        // Error no value detected
        if (empty($user->id_hash)) {
            return response()->json(
                [
                    'message' => 'Not authenticated user',
                ],
                Response::HTTP_UNAUTHORIZED
            );
        }

        // Validation rules for each item in the array
        $validator = Validator::make($request->all(), [
            'items.*.inventory_id' => 'required|string',
            'items.*.group_id' => 'required|string',
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

        // Initialize an array to store all updated items with old and new data
        $updatedItems = [];

        foreach ($request['items'] as $productUserInput) {
            $inventory = InventoryModel::where('inventory_id', $productUserInput['inventory_id'])->first();
            if (!$inventory) {
                return response()->json(
                    [
                        'message' => 'Data not found',
                    ],
                    Response::HTTP_NOT_FOUND
                );
            }

            // Get the old data before updating
            $oldData = $inventory->getOriginal();

            // Set new values dynamically based on input array
            foreach ($productUserInput as $key => $value) {
                $inventory->$key = $value;
            }

            // Check if any attributes have been changed
            if ($inventory->isDirty()) {
                // Update the inventory record
                $update = $inventory->save(); // Use save() instead of update()

                if ($update) {
                    // Add the updated item with old and new data to the array
                    $updatedItems[] = [
                        'inventory_id' => $productUserInput,
                        'old_data' => $oldData,
                        'new_data' => $inventory->toArray(),
                    ];
                } else {
                    return response()->json(
                        [
                            'message' => 'Failed to update Inventory records',
                        ],
                        Response::HTTP_INTERNAL_SERVER_ERROR
                    );
                }
            }
        }

        $this->updateLogs($request, $user->id_hash, $updatedItems);

        return response()->json(
            [
                'message' => 'Inventory records updated successfully',
            ],
            Response::HTTP_OK
        );
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
    public function storeLogs(Request $request, $idHash, $storeData)
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

    public function updateLogs(Request $request, $idHash, $storeData)
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
                // Check if $item is an array and has the specified field
                if (is_array($item) && array_key_exists($field, $item)) {
                    $itemData[$field] = $item[$field];
                }
            }
            $data[] = $itemData;

            // Create HistoryModel entry for each field in the item
            foreach ($fieldsToInclude as $field) {
                // Check if the field exists in the current item
                if (array_key_exists($field, $item)) {
                    // Create HistoryModel entry
                    $historyCreate = HistoryModel::create([
                        'user_id_hash' => $idHash,
                        'tbl_name' => 'inventory_tbl',
                        'column_name' => $field,
                        'value' => $item[$field], // Use the field value as the column value
                    ]);

                    if (!$historyCreate) {
                        return response()->json(['message' => 'Failed to create history for update inventory parent'], Response::HTTP_INTERNAL_SERVER_ERROR);
                    }
                }
            }
        }

        $details = json_encode($data, JSON_PRETTY_PRINT);

        // Create LogsModel entry
        $logEntry = LogsModel::create([
            'user_id_hash' => $idHash,
            'ip_address' => $request->ip(),
            'user_action' => 'UPDATE INVENTORY PARENT',
            'user_device' => $userAgent,
            'details' => $details,
        ]);

        if (!$logEntry) {
            return response()->json(['message' => 'Failed to update logs for update inventory parent'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }
}
