<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\InventoryModel;
use Illuminate\Support\Facades\DB;
use App\Models\InventoryProductModel;
use Illuminate\Support\Facades\Crypt;
use App\Http\Controllers\Helper\Helper;
use Illuminate\Support\Facades\Validator;
use Symfony\Component\HttpFoundation\Response;

class InventoryProductController extends Controller
{

    protected $fillable_attr_inventory_children, $helper;

    public function __construct(Helper $helper, InventoryProductModel $fillable_attr_inventory_children)
    {
        $this->fillable_attr_inventory_children = $fillable_attr_inventory_children;
        $this->helper = $helper;
    }

    public function index(Request $request)
    {
        $crud_settings = $this->fillable_attr_inventory_children->getApiAccountCrudSettings();
        $relative_settings = $this->fillable_attr_inventory_children->getApiAccountRelativeSettings();
        $view_settings = $this->fillable_attr_inventory_children->getViewRowTable();
        $arr_inventory_item = [];
        $all_inventory_items = [];

        // Authorize the user
        $user = $this->helper->authorizeUser($request);
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        $inventory_products = InventoryProductModel::get();
        foreach ($inventory_products as $inventory_product) {

            foreach ($this->fillable_attr_inventory_children->getFillableAttributes() as $getFillableAttribute) {
                if ($getFillableAttribute == 'inventory_product_id') {
                    $arr_inventory_item[$getFillableAttribute] = Crypt::encrypt($inventory_product->$getFillableAttribute);
                } else if ($getFillableAttribute == 'inventory_id') {
                    $arr_inventory_item[$getFillableAttribute] = Crypt::encrypt($inventory_product->$getFillableAttribute);
                } elseif (in_array($getFillableAttribute, $this->fillable_attr_inventory_children->arrToConvertToReadableDateTime())) {
                    $arr_inventory_item[$getFillableAttribute] = $this->helper->convertReadableTimeDate($inventory_product->$getFillableAttribute);
                } else {
                    $arr_inventory_item[$getFillableAttribute] = $inventory_product->$getFillableAttribute;
                }
            }

            // ***************************** //
            // Format Api
            $crud_action = $this->helper->formatApi(
                $crud_settings['prefix'],
                $crud_settings['payload'],
                $crud_settings['method'],
                $crud_settings['button_name'],
                $crud_settings['icon'],
                $crud_settings['container']
            );

            // Checking Id on other tbl if exist unset the api
            $is_exist_id_other_tbl = $this->helper->isExistIdOtherTbl($inventory_product->inventory_id, $this->fillable_attr_inventory_children->arrModelWithId());
            // Unset actions based on conditions
            if (!empty($is_exist_id_other_tbl) && $is_exist_id_other_tbl[0]['is_exist'] == 'yes') {
                foreach ($this->fillable_attr_inventory_children->unsetActions() as $unsetAction) {
                    $crud_action = array_filter($crud_action, function ($action) use ($unsetAction) {
                        return $action['button_name'] !== ucfirst($unsetAction);
                    });
                }
            }

            // Add the format Api Crud
            $arr_inventory_item['action'] = array_values($crud_action);
            // ***************************** //

            // ***************************** //
            // Add details on action crud
            foreach ($arr_inventory_item['action'] as &$action) {
                // Check if 'details' key doesn't exist, then add it
                if (!isset($action['details'])) {
                    $action['details'] = [];
                }

                // Populate details for each attribute
                foreach ($this->fillable_attr_inventory_children->arrDetails() as $arrDetails) {
                    $action['details'][] = [
                        'label' => "Product " . ucfirst($arrDetails),
                        'type' => 'input',
                        'value' => $arr_inventory_item[$arrDetails]
                    ];
                }
            }
            // ***************************** //

            // Add view on row item
            $arr_inventory_item['view'] = [[
                'url' => $view_settings['url'] . $arr_inventory_item['inventory_product_id'],
                'method' => $view_settings['method']
            ]];

            // Collect each inventory item
            $all_inventory_items[] = $arr_inventory_item;
        }

        // Final response structure
        $response = [
            'inventory_product' => $all_inventory_items,
            'column' => $this->helper->transformColumnName($this->fillable_attr_inventory_children->getFillableAttributes()),
            'buttons' => $this->helper->formatApi(
                $relative_settings['prefix'],
                $relative_settings['payload'],
                $relative_settings['method'],
                $relative_settings['button_name'],
                $relative_settings['icon'],
                $relative_settings['container']
            ),
            // 'filter' => $filter
        ];

        return response()->json(
            [
                'messages' => "Successfully retrieve data",
                'data' => $response
            ],
            Response::HTTP_OK
        );
    }

    public function show(Request $request, string $id)
    {
        $arr_inventory_product = [];

        // Authorize the user
        $user = $this->helper->authorizeUser($request);
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        $inventory_product = InventoryProductModel::where('inventory_id', Crypt::decrypt($id))->get();
        if ($inventory_product->isEmpty()) {
            return response()->json(
                [
                    'message' => 'Data not found',
                ],
                Response::HTTP_NOT_FOUND
            );
        }

        foreach ($inventory_product->toArray() as $toArray) {
            $arr_product = [];
            foreach ($this->fillable_attr_inventory_children->getFillableAttributes() as $getFillableAttribute) {
                if ($getFillableAttribute == 'inventory_product_id') {
                    $arr_product[$getFillableAttribute] = Crypt::encrypt($toArray[$getFillableAttribute]);
                } else if ($getFillableAttribute == 'inventory_id') {
                    $arr_product[$getFillableAttribute] = Crypt::encrypt($toArray[$getFillableAttribute]);
                } else if (in_array($getFillableAttribute, $this->fillable_attr_inventory_children->arrToConvertToReadableDateTime())) {
                    $arr_product[$getFillableAttribute] = $this->helper->convertReadableTimeDate($toArray[$getFillableAttribute]);
                } else {
                    $arr_product[$getFillableAttribute] = $toArray[$getFillableAttribute];
                }
            }
            $arr_inventory_product[] = $arr_product;
        }

        return response()->json(
            [
                'messages' => "Successfully retrieve data",
                'column' => $this->helper->transformColumnName($this->fillable_attr_inventory_children->getFillableAttributes()),
                'data' => $arr_inventory_product,
            ],
            Response::HTTP_OK
        );
    }

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

        // Validation rules for each item in the array
        $validator = Validator::make($request->all(), [
            'inventory_id' => 'required|string',
            'item_code' => 'required|string|max:255',
            'image' => 'nullable|image|mimes:jpeg,png,jpg,gif|max:2048',
            'description' => 'nullable',
            'is_refund' => 'nullable',
            'name' => 'required|string|max:500',
            'category' => 'required|string|max:500',
            'retail_price' => 'required|numeric',
            'discounted_price' => 'nullable|numeric',
            'stock' => 'required|numeric',
            'supplier_name' => 'nullable',
            'design' => 'nullable|string|max:500',
            'size' => 'nullable|string|max:500',
            'color' => 'nullable|string|max:500',
            'unit_supplier_price' => 'nullable|numeric',
        ]);

        // Check if validation fails
        if ($validator->fails()) {
            DB::rollBack();
            return response()->json(['message' => $validator->errors()], Response::HTTP_UNPROCESSABLE_ENTITY);
        }


        // Validate eu_device
        $result_validate_eu_device = $this->helper->validateEuDevice($request->input('eu_device'));
        if ($result_validate_eu_device) {
            return $result_validate_eu_device;
        }


        DB::beginTransaction();
        try {
            $decrypted_inventory_id = Crypt::decrypt($request->input('inventory_id'));

            // Retrieve the inventory record
            $inventory = InventoryModel::where('inventory_id', $decrypted_inventory_id)->first();
            // Check if inventory record exists
            if (!$inventory) {
                DB::rollBack();
                return response()->json([
                    'message' => 'Parent inventory ID not found',
                ], Response::HTTP_NOT_FOUND);
            }

            // Handle image upload if it exists for the current item
            if ($request->hasFile('image') && $request->file('image')->isValid()) {
                // Handle image upload 
                $arr_data_file = [
                    'custom_folder' => 'inventory-children',
                    'file_image' => $request->file('image'),
                    'image_actual_extension' => $request->file('image')->getClientOriginalExtension(),
                ];
                $file_name = $this->helper->handleUploadImage($arr_data_file);
            }

            // Create the InventoryProductModel instance with the selected attributes
            $result_to_create = $this->helper->arrStoreMultipleData($this->fillable_attr_inventory_children->arrToStores(), $request->all(), $file_name);
            $created = InventoryProductModel::create($result_to_create);
            if (!$created) {
                DB::rollBack();
                return response()->json(
                    ['message' => 'Failed to store Inventory Child'],
                    Response::HTTP_INTERNAL_SERVER_ERROR
                );
            }

            // Update the unique ID
            $update_unique_id = $this->helper->updateUniqueId($created, $this->fillable_attr_inventory_children->idToUpdate(), $created->id);
            if ($update_unique_id) {
                DB::rollBack();
                return $update_unique_id;
            }

            $created_items[] = $created;
            $eu_device = $request->input('eu_device');

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
            if ($log_result->getStatusCode() !== Response::HTTP_OK) {
                DB::rollBack();
                return $log_result;
            }

            DB::commit();

            return response()->json([
                'message' => 'Inventory records child stored successfully',
                'log_message' => $log_result
            ], Response::HTTP_OK);
        } catch (\Exception $e) {
            DB::rollBack();
            return response()->json(['message' => $e->getMessage()], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    public function storeMultiple(Request $request)
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
                ['message' => 'Missing items in the request'],
                Response::HTTP_INTERNAL_SERVER_ERROR
            );
        }

        $arr_items_error_fields = $this->fillable_attr_inventory_children->arrToStores();

        $validator = Validator::make($request->all(), [
            'items.*.inventory_id' => 'required|string',
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
            'items.*.design' => 'nullable|string|max:500',
            'items.*.size' => 'nullable|string|max:500',
            'items.*.color' => 'nullable|string|max:500',
            'items.*.unit_supplier_price' => 'nullable|numeric',
        ]);

        // Add custom validation rule for unique combination of name and category
        $validator->after(function ($validator) use ($request, $arr_items_error_fields) {
            foreach ($request['items'] as $index => $user_input) {
                $exists = InventoryModel::where('name', $user_input['name'])
                    ->where('category', $user_input['category'])
                    ->exists();

                if ($exists) {
                    foreach ($arr_items_error_fields as $field) {
                        $validator->errors()->add("items.$index.$field", 'Already exists.');
                    }
                }
            }
        });


        DB::beginTransaction();
        try {
            foreach ($request['items'] as $user_input) {
                $decrypted_inventory_id = Crypt::decrypt($user_input['inventory_id']);

                // Validate eu_device
                $result_validate_eu_device = $this->helper->validateEuDevice($user_input['eu_device']);
                if ($result_validate_eu_device) {
                    return $result_validate_eu_device;
                }

                // Retrieve the inventory record
                $inventory = InventoryModel::where('inventory_id', $decrypted_inventory_id)->first();
                // Check if inventory record exists
                if (!$inventory) {
                    DB::rollBack();
                    return response()->json([
                        'message' => 'Parent inventory ID not found',
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

                // Create the InventoryProductModel instance with the selected attributes
                $result_to_create = $this->helper->arrStoreMultipleData($this->fillable_attr_inventory_children->arrToStores(), $user_input, $file_name);
                $created = InventoryProductModel::create($result_to_create);
                if (!$created) {
                    DB::rollBack();
                    return response()->json(
                        ['message' => 'Failed to store Inventory Child'],
                        Response::HTTP_INTERNAL_SERVER_ERROR
                    );
                }

                // Update the unique ID
                $update_unique_id = $this->helper->updateUniqueId($created, $this->fillable_attr_inventory_children->idToUpdate(), $created->id);
                if ($update_unique_id) {
                    DB::rollBack();
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
                'user_action' => 'STORE MULTIPLE INVENTORY CHILD ITEMS',
            ];


            $log_result = $this->helper->log($request, $arr_data_logs);
            if ($log_result->getStatusCode() !== Response::HTTP_OK) {
                DB::rollBack();
                return $log_result;
            }

            DB::commit();

            return response()->json([
                'message' => 'Inventory records child stored successfully',
                'log_message' => $log_result
            ], Response::HTTP_OK);
        } catch (\Exception $e) {
            DB::rollBack();
            return response()->json(['message' => $e->getMessage()], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    public function update(Request $request)
    {
        $changes_for_log = [];
        $file_name = '';

        // Authorize the user
        $user = $this->helper->authorizeUser($request);
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        // Validation rules for each item in the array
        $validator = Validator::make($request->all(), [
            'inventory_product_id' => 'required|string',
            'item_code' => 'required|string|max:255',
            'image' => 'nullable|image|mimes:jpeg,png,jpg,gif|max:2048',
            'description' => 'nullable',
            'is_refund' => 'nullable',
            'name' => 'required|string|max:500',
            'category' => 'required|string|max:500',
            'retail_price' => 'required|numeric',
            'discounted_price' => 'nullable|numeric',
            'stock' => 'required|numeric',
            'supplier_name' => 'nullable',
            'design' => 'nullable|string|max:500',
            'size' => 'nullable|string|max:500',
            'color' => 'nullable|string|max:500',
            'unit_supplier_price' => 'nullable|numeric',
            'eu_device' => 'required|string',
        ]);

        // Check if validation fails
        if ($validator->fails()) {
            return response()->json(['message' => $validator->errors()], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        // Validate eu_device
        $result_validate_eu_device = $this->helper->validateEuDevice($request->input('eu_device'));
        if ($result_validate_eu_device) {
            return $result_validate_eu_device;
        }



        DB::beginTransaction();
        try {
            // Decrypted id
            $decrypted_inventory_product_id = Crypt::decrypt($request->input('inventory_product_id'));
            // Check if inventory record exists
            $inventory = InventoryProductModel::where('inventory_product_id', $decrypted_inventory_product_id)
                ->first();
            if (!$inventory) {
                return response()->json(['message' => 'Data not found'], Response::HTTP_NOT_FOUND);
            }

            // Handle image upload if it exists for the current item
            if ($request->hasFile('image') && $request->file('image')->isValid()) {
                // Handle image upload 
                $arr_data_file = [
                    'custom_folder' => 'inventory-children',
                    'file_image' => $request->file('image'),
                    'image_actual_extension' => $request->file('image')->getClientOriginalExtension(),
                ];
                $file_name = $this->helper->handleUploadImage($arr_data_file);
            }

            // Get the changes of the fields
            $result_changes_item_for_logs = $this->helper->updateLogsOldNew($inventory, $this->fillable_attr_inventory_children->arrToUpdates(), $request->all(), $file_name);
            $changes_for_log[] = [
                'inventory_product_id' => $decrypted_inventory_product_id,
                'fields' => $result_changes_item_for_logs,
            ];

            // Check if there are changes for logs
            $result_changes_logs = $this->helper->checkIfTheresChangesLogs($changes_for_log);
            if ($result_changes_logs) {
                DB::rollBack();
                return $result_changes_logs;
            }

            // Update Multiple Data
            $result_update_multi_data = $this->helper->arrUpdateMultipleData($inventory, $this->fillable_attr_inventory_children->arrToUpdates(), $request->all(), $file_name);
            if ($result_update_multi_data) {
                DB::rollBack();
                return $result_update_multi_data;
            }

            $eu_device = $request->input('eu_device');

            // Arr Data Logs
            $arr_data_logs = [
                'user_device' => $eu_device,
                'user_id' => $user->user_id,
                'is_sensitive' => 0,
                'is_history' => 0,
                'log_details' => $changes_for_log,
                'user_action' => 'UPDATE INVENTORY CHILDREN',
            ];

            // Logs
            $log_result = $this->helper->log($request, $arr_data_logs);
            if ($log_result->getStatusCode() !== Response::HTTP_OK) {
                DB::rollBack();
                return $log_result;
            }

            DB::commit();

            return response()->json([
                'message' => 'Successfully update inventory child',
                'log_message' => $log_result
            ], Response::HTTP_OK);
        } catch (\Exception $e) {
            DB::rollBack();
            return response()->json(['message' => $e->getMessage()], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    public function updateMultiple(Request $request)
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

        $arr_items_error_fields = $this->fillable_attr_inventory_children->arrToUpdates();

        $validator = Validator::make($request->all(), [
            'items.*.inventory_id' => 'required|string',
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

        // Add custom validation rule for unique combination of name and category
        $validator->after(function ($validator) use ($request, $arr_items_error_fields) {
            foreach ($request['items'] as $index => $user_input) {
                $exists = InventoryModel::where('name', $user_input['name'])
                    ->where('category', $user_input['category'])
                    ->exists();

                if ($exists) {
                    foreach ($arr_items_error_fields as $field) {
                        $validator->errors()->add("items.$index.$field", 'Already exists.');
                    }
                }
            }
        });

        DB::beginTransaction();

        try {
            foreach ($request['items'] as $user_input) {
                // Decrypted id
                $decrypted_inventory_product_id = Crypt::decrypt($user_input['inventory_product_id']);

                // Validate eu_device
                $result_validate_eu_device = $this->helper->validateEuDevice($user_input['eu_device']);
                if ($result_validate_eu_device) {
                    return $result_validate_eu_device;
                }

                $inventory = InventoryProductModel::where('inventory_product_id', $decrypted_inventory_product_id)
                    ->first();
                if (!$inventory) {
                    DB::rollBack();
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
                $result_changes_item_for_logs = $this->helper->updateLogsOldNew($inventory, $this->fillable_attr_inventory_children->arrToUpdates(), $user_input, $file_name);
                $changes_for_log[] = [
                    'inventory_product_id' => $user_input['inventory_product_id'],
                    'fields' => $result_changes_item_for_logs,
                ];

                // Update Multiple Data
                $result_update_multi_data = $this->helper->arrUpdateMultipleData($inventory, $this->fillable_attr_inventory_children->arrToUpdates(), $user_input, $file_name);
                if ($result_update_multi_data) {
                    DB::rollBack();
                    return $result_update_multi_data;
                }

                $eu_device = $user_input['eu_device'];
            }

            // Check if there are changes for logs
            $result_changes_logs = $this->helper->checkIfTheresChangesLogs($changes_for_log);
            if ($result_changes_logs) {
                DB::rollBack();
                return $result_changes_logs;
            }

            // Arr Data Logs
            $arr_data_logs = [
                'user_device' => $eu_device,
                'user_id' => $user->user_id,
                'is_sensitive' => 0,
                'is_history' => 0,
                'log_details' => $changes_for_log,
                'user_action' => 'UPDATE MULTIPLE INVENTORY CHILD ITEMS',
            ];

            // Logs
            $log_result = $this->helper->log($request, $arr_data_logs);
            if ($log_result->getStatusCode() !== Response::HTTP_OK) {
                DB::rollBack();
                return $log_result;
            }

            DB::commit();

            return response()->json([
                'message' => 'Successfully update inventory child',
                'log_message' => $log_result
            ], Response::HTTP_OK);
        } catch (\Exception $e) {
            DB::rollBack();
            return response()->json(['message' => $e->getMessage()], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    public function destroy(Request $request)
    {
        $arr_log_details = [];

        // Authorize the user
        $user = $this->helper->authorizeUser($request);
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        // Check if 'inventory_product_id' and 'eu_device' are provided
        $validator = Validator::make($request->all(), [
            'inventory_product_id' => 'required|string',
            'inventory_id' => 'required|string',
            'eu_device' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json(['message' => $validator->errors()], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        // Validate 'eu_device'
        $result_validate_eu_device = $this->helper->validateEuDevice($request->eu_device);
        if ($result_validate_eu_device) {
            return $result_validate_eu_device;
        }

        DB::beginTransaction();

        try {
            $decrypted_inventory_product_id = Crypt::decrypt($request->inventory_product_id);
            $decrypted_inventory_id = Crypt::decrypt($request->inventory_id);

            $inventory = InventoryModel::where('inventory_id', $decrypted_inventory_id)->first();
            if (!$inventory) {
                return response()->json(['message' => 'Data not found'], Response::HTTP_NOT_FOUND);
            }

            $inventory_product = InventoryProductModel::where('inventory_id', $decrypted_inventory_id)
                ->where('inventory_product_id', $decrypted_inventory_product_id)->first();
            if (!$inventory_product) {
                return response()->json(['message' => 'Data not found'], Response::HTTP_NOT_FOUND);
            }

            // Checking Id on other tbl if exist unset the the api
            $is_exist_id_other_tbl = $this->helper->isExistIdOtherTbl($inventory_product->inventory_product_id, $this->fillable_attr_inventory_children->arrModelWithId());

            // Check if 'is_exist' is 'yes' in the first element and then unset it
            if (!empty($is_exist_id_other_tbl) && $is_exist_id_other_tbl[0]['is_exist'] == 'yes') {
                return response()->json(['message' => 'Can\'t delete because this id exist on other table'], Response::HTTP_NOT_FOUND);
            }

            foreach ($this->fillable_attr_inventory_children->getFillableAttributes() as $getFillableAttributes) {
                $arr_log_details['fields'][$getFillableAttributes] = $inventory_product->$getFillableAttributes;
            }

            // Delete the inventory record
            if (!$inventory->delete()) {
                DB::rollBack();
                return response()->json(['message' => 'Failed to delete'], Response::HTTP_UNPROCESSABLE_ENTITY);
            }

            $eu_device = $request->input('eu_device');

            // Arr Data Logs
            $arr_data_logs = [
                'user_device' => $eu_device,
                'user_id' => $user->user_id,
                'is_sensitive' => 0,
                'is_history' => 0,
                'log_details' => $arr_log_details,
                'user_action' => 'DELETE INVENTORY CHILD',
            ];

            // Logs
            $log_result = $this->helper->log($request, $arr_data_logs);
            if ($log_result->getStatusCode() !== Response::HTTP_OK) {
                DB::rollBack();
                return $log_result;
            }

            DB::commit();

            return response()->json([
                'message' => 'Successfully deleted inventory record',
                'log_message' => $log_result
            ], Response::HTTP_OK);
        } catch (\Exception $e) {
            DB::rollBack();
            return response()->json(['message' => $e->getMessage()], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }


    public function destroyMultiple(Request $request)
    {
        $arr_log_details = [];

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
            'items.*.inventory_product_id' => 'required|string',
            'items.*.inventory_id' => 'required|string',
            'items.*.eu_device' => 'required|string',
        ]);

        $arr_items_error_fields = $this->fillable_attr_inventory_children->arrToDeletes();

        // Check if validation fails
        if ($validator->fails()) {
            $errors = $validator->errors()->toArray();
            $formattedErrors = [];

            foreach ($request['items'] as $index => $item) {
                $itemErrors = [];

                foreach ($arr_items_error_fields as $field) {
                    if (isset($errors["items.$index.$field"])) {
                        $itemErrors[$field] = array_map(function ($msg) use ($index) {
                            return preg_replace("/items\.$index\./", '', $msg);
                        }, $errors["items.$index.$field"]);
                    }
                }

                if (!empty($itemErrors)) {
                    $formattedErrors[$index] = $itemErrors;
                }
            }

            return response()->json(['message' => array_values($formattedErrors)], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        DB::beginTransaction();

        try {
            foreach ($request['items'] as $user_input) {

                // Decrypted id
                $decrypted_inventory_product_id = Crypt::decrypt($user_input['inventory_product_id']);
                $decrypted_inventory_id = Crypt::decrypt($user_input['inventory_id']);

                $inventory = InventoryModel::where('inventory_id', $decrypted_inventory_id)->first();
                if (!$inventory) {
                    return response()->json(['message' => 'Data not found'], Response::HTTP_NOT_FOUND);
                }

                $inventory_product = InventoryProductModel::where('inventory_id', $decrypted_inventory_id)
                    ->where('inventory_product_id', $decrypted_inventory_product_id)->first();
                if (!$inventory_product) {
                    return response()->json(['message' => 'Data not found'], Response::HTTP_NOT_FOUND);
                }


                // Validate eu_device
                $result_validate_eu_device = $this->helper->validateEuDevice($user_input['eu_device']);
                if ($result_validate_eu_device) {
                    return $result_validate_eu_device;
                }

                // Checking Id on other tbl if exist unset the api
                $is_exist_id_other_tbl = $this->helper->isExistIdOtherTbl($inventory_product->inventory_product_id, $this->fillable_attr_inventory_children->arrModelWithId());

                // Check if 'is_exist' is 'yes' in the first element and then unset it
                if (!empty($is_exist_id_other_tbl) && $is_exist_id_other_tbl[0]['is_exist'] == 'yes') {
                    return response()->json(['message' => 'Can\'t delete because this id exist on other table'], Response::HTTP_NOT_FOUND);
                }

                // Get details to log
                $log_details = [];
                foreach ($this->fillable_attr_inventory_children->getFillableAttributes() as $getFillableAttributes) {
                    $log_details[$getFillableAttributes] = $inventory_product->$getFillableAttributes;
                }
                $arr_log_details[] = $log_details;


                // Delete the inventory
                if (!$inventory_product->delete()) {
                    DB::rollBack();
                    return response()->json(['message' => 'Failed to delete inventory'], Response::HTTP_UNPROCESSABLE_ENTITY);
                }

                $eu_device = $user_input['eu_device'];
            }

            // Arr Data Logs
            $arr_data_logs = [
                'user_device' => $eu_device,
                'user_id' => $user->user_id,
                'is_sensitive' => 0,
                'is_history' => 0,
                'log_details' => $arr_log_details,
                'user_action' => 'DELETE MULTIPLE INVENTORY CHILD ITEMS',
            ];

            // Logs
            $log_result = $this->helper->log($request, $arr_data_logs);
            if ($log_result->getStatusCode() !== Response::HTTP_OK) {
                DB::rollBack();
                return $log_result;
            }

            DB::commit();

            return response()->json([
                'message' => 'Successfully deleted data',
                'log_message' => $log_result
            ], Response::HTTP_OK);
        } catch (\Exception $e) {
            DB::rollBack();
            return response()->json(['message' => $e->getMessage()], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }
}
