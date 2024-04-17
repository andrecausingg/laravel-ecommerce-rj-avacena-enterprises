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

    protected $fillableAttributes, $unsets, $userInputFields;

    public function __construct()
    {
        $this->unsets = config('a-global.Unset-Timestamp');

        $InventoryModel = new InventoryModel();
        $this->fillableAttributes = $InventoryModel->getFillableAttributes();
    }


    /**
     * Display a listing of the resource.
     */
    public function index(Request $request)
    {
        $arrInventory = [];

        // Authorize the user
        $user = $this->authorizeUser($request);

        // Check if authenticated user
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        $inventoryParents = InventoryModel::get();
        foreach ($inventoryParents as $inventoryParent) {
            $arrInventoryItem = [];
            $arrInventoryItem['inventory_parent'] = $inventoryParent;

            $inventoryChilds = InventoryProductModel::where('inventory_group_id', $inventoryParent->group_id)->get();
            $arrInventoryItem['inventory_parent']['variant'] =  $inventoryChilds->count();
            $arrInventoryItem['inventory_parent']['stock'] = $inventoryChilds->sum('stock');
            $arrInventoryItem['inventory_parent']['inventory_children'] = $inventoryChilds->toArray();

            $arrInventory[] = $arrInventoryItem;
        }

        return response()->json(
            [
                'message' => 'Successfully Retrieve Data',
                'result' => $arrInventory
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
                    'inventory_id' => 'inv_id-' . $lastInsertedId,
                    'group_id' => "inv_gro_id-" . $lastInsertedId,
                ]);

                $createdItems[] = $created;
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

        return response()->json([
            'message' => 'Inventory records parent store successfully',
            'log_message' => $logResult
        ], Response::HTTP_OK);
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

        if (empty($user->user_id)) {
            return response()->json(
                [
                    'message' => 'Not authenticated user',
                ],
                Response::HTTP_INTERNAL_SERVER_ERROR
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
                'inventory_id' => $productUserInput['inventory_id'],
                'group_id' => $productUserInput['group_id'],
                'fields' => $changesForLogsItem,
            ];

            // Update the inventory info
            foreach ($this->fillableAttributes as $fillableAttribute) {
                $inventory->$fillableAttribute = $productUserInput[$fillableAttribute];
            }

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
            'message' => 'All inventory parent records updated successfully',
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
            'user_action' => 'UPDATE INVENTORY PARENT',
            'user_device' => $userAgent,
            'details' => json_encode($arr, JSON_PRETTY_PRINT),
        ]);

        if ($log) {
            $log->update([
                'log_id' => 'log_id-'  . $log->id,
            ]);
        } else {
            return response()->json(['message' => 'Failed to update logs for update inventory parent'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        return response()->json(['message' => 'Successfully update inventory parent'], Response::HTTP_OK);
    }
}
