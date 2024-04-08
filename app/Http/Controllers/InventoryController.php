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

                $this->storeLogs($request, $user->user_id, $created);
            } else {
                return response()->json([
                        'message' => 'Failed to store Inventory Parents',
                    ],Response::HTTP_INTERNAL_SERVER_ERROR
                );
            }
        }

        return response()->json([
                'message' => 'Inventory records parent store successfully',
            ],Response::HTTP_OK
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
        // Initialize
        $changesForLogs = [];
        $fields = config('inventory.inventory');

        // Authorize the user
        $user = $this->authorizeUser($request);

        // Check if authenticated user
        if (empty($user->id_hash)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
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
            return response()->json(['message' => $validator->errors()], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        // Input User
        foreach ($request['items'] as $productUserInput) {
            // Retrieve the inventory record
            $inventory = InventoryModel::where('inventory_id', $productUserInput['inventory_id'])->first();

            // Check if inventory record exists
            if (!$inventory) {
                return response()->json(['message' => 'Data not found'], Response::HTTP_NOT_FOUND);
            }

            // Field to check if not same value on database then record it on logs
            $changesForLogsItem = [];

            foreach ($fields as $field) {
                $existingValue = $inventory->$field ?? null;
                $newValue = $productUserInput[$field] ?? null;

                // Check if the value has changed
                if ($existingValue !== $newValue) {
                    $changesForLogsItem[$field] = [
                        'old' => $existingValue,
                        'new' => $newValue,
                    ];
                }
            }

            // Log the changes for the current item
            $changesForLogs[] = [
                'inventory_id' => $productUserInput['inventory_id'],
                'fields' => $changesForLogsItem,
            ];

            // Update the inventory info
            foreach ($fields as $field) {
                $inventory->$field = $productUserInput[$field];
            }

            if (!$inventory->save()) {
                return response()->json(['message' => 'Failed to update inventory'], Response::HTTP_INTERNAL_SERVER_ERROR);
            }
        }

        return response()->json(['message' => $changesForLogs], Response::HTTP_OK);
        // Log all changes
        $this->updateLogs($request, $user->id_hash, $changesForLogs);

        return response()->json(['message' => 'All inventory parent records updated successfully'], Response::HTTP_OK);
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
    // public function storeLogs(Request $request, $userId, $storeData)
    // {
    //     // Get Device Information
    //     $userAgent = $request->header('User-Agent');

    //     // Define the fields to include in the logs
    //     $fieldsToInclude = [
    //         'inventory_id', 'group_id', 'name', 'category',
    //     ];

    //     // Loop through each created item and add them to data
    //     $data = [];
    //     foreach ($storeData as $item) {
    //         $itemData = [];
    //         foreach ($fieldsToInclude as $field) {
    //             $itemData[$field] = $item->$field;
    //         }
    //         $data[] = $itemData;
    //     }

    //     $details = json_encode($data, JSON_PRETTY_PRINT);

    //     // Create LogsModel entry
    //     $logEntry = LogsModel::create([
    //         'user_id_hash' => $userId,
    //         'ip_address' => $request->ip(),
    //         'user_action' => 'STORE INVENTORY PARENT',
    //         'user_device' => $userAgent,
    //         'details' => $details,
    //     ]);

    //     if (!$logEntry) {
    //         return response()->json(['message' => 'Failed to store logs for store inventory parent'], Response::HTTP_INTERNAL_SERVER_ERROR);
    //     }
    // }

    public function storeLogs($request, $userId, $logDetails)
    {

        $arr = [];
        $arr['user_id'] = $userId;
        $arr['fields'] = is_array($logDetails) ? json_encode($logDetails) : $logDetails;

        // Get Device Information
        $userAgent = $request->header('User-Agent');

        // Create LogsModel entry
        $log = LogsModel::create([
            'user_id' => $userId,
            'ip_address' => $request->ip(),
            'user_action' => 'STORE INVENTORY PARENT',
            'user_device' => $userAgent,
            'details' => json_encode($arr, JSON_PRETTY_PRINT),
        ]);

        if ($log) {
            $log->update([
                'log_id' => 'log_id-'  . $log->id,
            ]);
        } else {
            return response()->json(['message' => 'Failed to store logs for store inventory parent'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        return response()->json(['message' => 'Successfully stored inventory parent'], Response::HTTP_OK);
    }

    public function updateLogs(Request $request, $idHash, $changesForLogs)
    {
        // Get Device Information
        $userAgent = $request->header('User-Agent');

        // Define the fields to include in the logs
        $fieldsToInclude = [
            'inventory_id', 'group_id', 'name', 'category',
        ];

        // Create LogsModel entry for each change in $changesForLogs
        foreach ($changesForLogs as $change) {
            // Loop through fields for the current inventory item
            foreach ($change['fields'] as $field => $changeDetails) {
                $logDetails['fields'][$field] = [
                    'old' => $changeDetails['old'],
                    'new' => $changeDetails['new'],
                ];

                // Create HistoryModel entry
                $historyCreate = HistoryModel::create([
                    'user_id_hash' => $idHash, // User Perform Changes
                    'tbl_name' => 'inventory_tbl',
                    'column_name' => $field,
                    'value' => $changeDetails['old'],
                    'inventory_id' => $inventoryId,
                ]);

                if (!$historyCreate) {
                    return response()->json(['message' => 'Failed to create history for inventory parent'], Response::HTTP_INTERNAL_SERVER_ERROR);
                }
            }

            $details = json_encode($logDetails, JSON_PRETTY_PRINT);

            // Create LogsModel entry for the current inventory item
            $logEntry = LogsModel::create([
                'user_id_hash' => $idHash,
                'inventory_id' => $inventoryId,
                'ip_address' => $request->ip(),
                'user_action' => 'UPDATE PARENT INVENTORY',
                'user_device' => $userAgent,
                'details' => $details,
            ]);

            if (!$logEntry) {
                return response()->json(['message' => 'Failed to update logs for inventory parent'], Response::HTTP_INTERNAL_SERVER_ERROR);
            }
        }

        return response()->json(['message' => 'Successfully updated logs for inventory parent'], Response::HTTP_OK);
    }
}
