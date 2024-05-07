<?php

namespace App\Http\Controllers;

use App\Models\LogsModel;
use Illuminate\Support\Str;
use Illuminate\Http\Request;
use App\Models\InventoryModel;
use App\Models\InventoryProductModel;
use Illuminate\Support\Facades\Crypt;
use App\Http\Controllers\Helper\Helper;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\Validator;
use Symfony\Component\HttpFoundation\Response;

class InventoryProductController extends Controller
{

    protected $fillableAttrInventoryChildren, $helper;

    public function __construct(Helper $helper, InventoryProductModel $fillableAttrInventoryChildren)
    {
        $this->fillableAttrInventoryChildren = $fillableAttrInventoryChildren;
        $this->helper = $helper;
    }

    /**
     * Display a listing of the resource.
     */
    public function index(Request $request)
    {
        // Authorize the user
        $user = $this->helper->authorizeUser($request);
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
        $file_name = '';
        // Initialize an array to store all created items
        $created_items = [];

        // Authorize the user
        $user = $this->helper->authorizeUser($request);
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
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
            'items.*.inventory_id' => 'required|string|max:500',
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
            'items.*.design' => 'nullable|string|max:500',
            'items.*.size' => 'nullable|string|max:500',
            'items.*.color' => 'nullable|string|max:500',
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

        foreach ($request['items'] as $user_input) {
            // Validate eu_device
            $result_validate_eu_device = $this->helper->validateEuDevice($user_input['eu_device']);
            if ($result_validate_eu_device) {
                return $result_validate_eu_device;
            }

            // Retrieve the inventory record
            $inventory = InventoryModel::where('inventory_id', $user_input['inventory_id'])->first();
            // Check if inventory record exists
            if (!$inventory) {
                return response()->json([
                    'message' => 'Parent inventory I.D not found',
                ], Response::HTTP_NOT_FOUND);
            }

            // Handle image upload if it exists for the current item
            if (isset($user_input['image']) && $user_input['image']->isValid()) {
                // Handle image upload 
                $arr_data_file = [
                    'custom_folder' => 'inventory-children',
                    'file_image' => $user_input['image'],
                    'image_actual_extension' => $user_input['image']->getClientOriginalExtension(),
                ];
                $file_name = $this->helper->handleUploadImage($arr_data_file);
            }

            // Create the InventoryModel instance with the selected attributes
            $result_to_create = $this->helper->storeMultipleData($this->fillableAttrInventoryChildren->arrToStores(), $user_input, $file_name);
            $created = InventoryProductModel::create($result_to_create);
            if (!$created) {
                return response()->json(
                    [
                        'message' => 'Failed to store Inventory Child',
                    ],
                    Response::HTTP_INTERNAL_SERVER_ERROR
                );
            }

            // Update the unique I.D
            $update_unique_id = $this->helper->updateUniqueId($created, $this->fillableAttrInventoryChildren->idToUpdate(), $created->id);
            if ($update_unique_id) {
                return $update_unique_id;
            }

            $created_items[] = $created;
            $eu_device = $user_input['eu_device'];
        }

        // Arr Data Logs
        $arr_data_logs = [
            'user_device' => $eu_device,
            'user_id' => $user->user_id,
            'is_sensitive' => 0,
            'is_history' => 0,
            'log_details' => $created_items,
            'user_action' => 'STORE INVENTORY CHILD',
        ];

        $log_result = $this->helper->log($request, $arr_data_logs);

        return response()->json(
            [
                'message' => 'Inventory records child store successfully',
                'log_message' => $log_result
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
        $changes_for_log = [];
        $file_name = '';

        // Authorize the user
        $user = $this->helper->authorizeUser($request);
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        // Check if 'items' key exists in the request
        if (!$request->has('items') || empty($request['items'])) {
            return response()->json(['message' => 'Missing or empty items in the request'], Response::HTTP_BAD_REQUEST);
        }

        // Validation rules for each item in the array
        $validator = Validator::make($request->all(), [
            'items.*.inventory_id' => 'required|string|max:500',
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
            'items.*.design' => 'nullable|string|max:500',
            'items.*.size' => 'nullable|string|max:500',
            'items.*.color' => 'nullable|string|max:500',
            'items.*.unit_supplier_price' => 'nullable|numeric',
            'items.*.eu_device' => 'required|string',
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

        foreach ($request['items'] as $user_input) {
            // Validate eu_device
            $result_validate_eu_device = $this->helper->validateEuDevice($user_input['eu_device']);
            if ($result_validate_eu_device) {
                return $result_validate_eu_device;
            }

            $inventory = InventoryProductModel::where('inventory_product_id', $user_input['inventory_product_id'])->first();
            if (!$inventory) {
                return response()->json(['message' => 'Data not found'], Response::HTTP_NOT_FOUND);
            }

            // Handle image upload if it exists for the current item
            if (isset($user_input['image']) && $user_input['image']->isValid()) {
                // Handle image upload 
                $arr_data_file = [
                    'custom_folder' => 'inventory-children',
                    'file_image' => $user_input['image'],
                    'image_actual_extension' => $user_input['image']->getClientOriginalExtension(),
                ];
                $file_name = $this->helper->handleUploadImage($arr_data_file);
            }

            // Get the changes of the fields
            $result_changes_item_for_logs = $this->helper->updateLogsOldNew($inventory, $this->fillableAttrInventoryChildren->arrToUpdates(), $user_input, $file_name);
            $changes_for_log[] = [
                'inventory_product_id' => $user_input['inventory_product_id'],
                'fields' => $result_changes_item_for_logs,
            ];

            // Update Multiple Data
            $result_update_multi_data = $this->helper->updateMultipleData($inventory, $this->fillableAttrInventoryChildren->arrToUpdates(), $user_input, $file_name);
            if ($result_update_multi_data) {
                return $result_update_multi_data;
            }

            $eu_device = $user_input['eu_device'];
        }

        // Check if theres Changes Logs
        $result_changes_logs = $this->helper->checkIfTheresChangesLogs($changes_for_log);
        if ($result_changes_logs) {
            return $result_changes_logs;
        }

        // Arr Data Logs
        $arr_data_logs = [
            'user_device' => $eu_device,
            'user_id' => $user->user_id,
            'is_sensitive' => 1,
            'is_history' => 0,
            'log_details' => $changes_for_log,
            'user_action' => 'UPDATE INVENTORY CHILDREN',
        ];

        // Logs
        $log_result = $this->helper->log($request, $arr_data_logs);

        return response()->json([
            'message' => 'Successfully update inventory child',
            'log_message' => $log_result
        ], Response::HTTP_OK);
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(Request $request)
    {
        $arr_log_details = [];

        // Authorize the user
        $user = $this->helper->authorizeUser($request);
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        // Validation rules for each item in the array
        $validator = Validator::make($request->all(), [
            'inventory_id' => 'required|string',
            'eu_device' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json(['message' => $validator->errors()], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        // Validate eu_device
        $result_validate_eu_device = $this->helper->validateEuDevice($request->eu_device);
        if ($result_validate_eu_device) {
            return $result_validate_eu_device;
        }

        $inventory = InventoryProductModel::where('inventory_product_id', Crypt::decrypt($request->inventory_id))->first();
        if (!$inventory) {
            return response()->json(['message' => 'Data not found'], Response::HTTP_NOT_FOUND);
        }
        foreach ($this->fillableAttrInventoryChildren->getFillableAttributes() as $getFillableAttributes) {
            $arr_log_details['fields'][$getFillableAttributes] = $inventory->$getFillableAttributes;
        }

        // Delete the user
        if (!$inventory->delete()) {
            return response()->json(['message' => 'Failed to store'], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        // Arr Data Logs
        $arr_data_logs = [
            'user_device' => $request->eu_device,
            'user_id' => $user->user_id,
            'is_sensitive' => 0,
            'is_history' => 0,
            'log_details' => $arr_log_details,
            'user_action' => 'DELETE INVENTORY CHILD',
        ];

        // Logs
        $log_result = $this->helper->log($request, $arr_data_logs);

        return response()->json([
            'message' => 'Successfully created user',
            'log_message' => $log_result
        ], Response::HTTP_OK);
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
