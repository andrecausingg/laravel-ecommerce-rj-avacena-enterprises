<?php

namespace App\Http\Controllers;

use App\Models\LogsModel;
use Illuminate\Http\Request;
use App\Models\InventoryModel;
use Illuminate\Support\Carbon;
use App\Models\InventoryProductModel;
use Illuminate\Support\Facades\Crypt;
use App\Http\Controllers\Helper\Helper;
use App\Models\PurchaseModel;
use Illuminate\Support\Facades\Validator;
use Symfony\Component\HttpFoundation\Response;
use Illuminate\Support\Facades\DB;

class InventoryController extends Controller
{

    protected $helper, $fillable_attr_inventorys, $fillable_attr_inventory_children;

    public function __construct(Helper $helper, InventoryModel $fillable_attr_inventorys, InventoryProductModel $fillable_attr_inventory_children)
    {
        $this->helper = $helper;
        $this->fillable_attr_inventorys = $fillable_attr_inventorys;
        $this->fillable_attr_inventory_children = $fillable_attr_inventory_children;
    }

    /**
     * Display a listing of the resource.
     */
    public function index(Request $request)
    {
        $arr_inventory = [];
        $crud_settings = $this->fillable_attr_inventorys->getApiAccountCrudSettings();
        $relative_settings = $this->fillable_attr_inventorys->getApiAccountRelativeSettings();
        $arr_inventory_item = [];
        $arr_parent_inventory_data = [];

        // Authorize the user
        $user = $this->helper->authorizeUser($request);
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        $inventory_parents = InventoryModel::get();
        foreach ($inventory_parents as $inventory_parent) {
            foreach ($this->fillable_attr_inventorys->getFillableAttributes() as $getFillableAttribute) {
                if ($getFillableAttribute == 'inventory_id') {
                    $arr_parent_inventory_data[$getFillableAttribute] = Crypt::encrypt($inventory_parent->$getFillableAttribute);
                } else if (in_array($getFillableAttribute, $this->fillable_attr_inventorys->arrToConvertToReadableDateTime())) {
                    $arr_parent_inventory_data[$getFillableAttribute] = $this->helper->convertReadableTimeDate($inventory_parent->$getFillableAttribute);
                } else {
                    $arr_parent_inventory_data[$getFillableAttribute] = $inventory_parent->$getFillableAttribute;
                }
            }

            $arr_inventory_item = $arr_parent_inventory_data;
            $inventory_children = InventoryProductModel::where('inventory_id', $inventory_parent->inventory_id)->get();
            $arr_inventory_item['variant'] =  $inventory_children->count();
            $arr_inventory_item['stock'] = $inventory_children->sum('stock');


            // TODO : fix the total sales
            // Calculate total sales for all inventory items including both discounted and retail prices
            $total_sales = 0;
            foreach ($inventory_children as $child) {
                if ($child->discounted_price != null) {
                    $total_sales += $child->discounted_price;
                } else {
                    $total_sales += $child->retail_price;
                }
            }
            $arr_inventory_item['total_sales'] = $total_sales;


            // Format Api
            $crud_action = $this->helper->formatApi(
                $crud_settings['prefix'],
                $crud_settings['api_with_payloads'],
                $crud_settings['methods'],
                $crud_settings['button_names'],
                $crud_settings['icons'],
                $crud_settings['actions']
            );

            // Checking Id on other tbl if exist unset the the api
            $is_exist_id_other_tbl = $this->helper->isExistIdOtherTbl($inventory_parent->inventory_id, $this->fillable_attr_inventorys->arrModelWithId());

            // Check if 'is_exist' is 'yes' in the first element and then unset it
            if (!empty($is_exist_id_other_tbl) && $is_exist_id_other_tbl[0]['is_exist'] == 'yes') {
                foreach ($this->fillable_attr_inventorys->unsetActions() as $unsetAction) {
                    unset($crud_action[$unsetAction]);
                }
            }

            // Add the format Api Crud
            $arr_inventory_item['action'] = [
                $crud_action
            ];

            // Data
            $arr_inventory[] = $arr_inventory_item;
        }

        // Final response structure
        $response = [
            'data' => $arr_inventory,
            'column' => $this->helper->transformColumnName($this->fillable_attr_inventorys->getFillableAttributes()),
            'relative' => [$this->helper->formatApi(
                $relative_settings['prefix'],
                $relative_settings['api_with_payloads'],
                $relative_settings['methods'],
                $relative_settings['button_names'],
                $relative_settings['icons'],
                $relative_settings['actions']
            )],
            // 'filter' => $filter
        ];

        return response()->json(
            [
                'message' => 'Successfully Retrieve Data',
                'result' => $response
            ],
            Response::HTTP_OK
        );
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(Request $request)
    {
        // Initialize an array to store all created items
        $created_items = [];
        $eu_device = '';

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
            'items.*.name' => 'required|string|max:255',
            'items.*.category' => 'required|string|max:255',
            'items.*.eu_device' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json(['message' => $validator->errors()], Response::HTTP_BAD_REQUEST);
        }

        // Add custom validation rule for unique combination of name and category
        $validator->after(function ($validator) use ($request) {
            foreach ($request->input('items') as $item) {
                $exists = InventoryModel::where('name', $item['name'])
                    ->where('category', $item['category'])
                    ->exists();

                if ($exists) {
                    $validator->errors()->add('items', 'The combination of name and category already exists.');
                }
            }
        });

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

            // Create the InventoryModel instance with the selected attributes
            $result_to_create = $this->helper->arrStoreMultipleData($this->fillable_attr_inventorys->arrToStores(), $user_input);
            $created = InventoryModel::create($result_to_create);
            if (!$created) {
                return response()->json(
                    [
                        'message' => 'Failed to store Inventory Parent'
                    ],
                    Response::HTTP_INTERNAL_SERVER_ERROR
                );
            }

            // Update the unique I.D
            $update_unique_id = $this->helper->updateUniqueId($created, $this->fillable_attr_inventorys->idToUpdate(), $created->id);
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
            'user_action' => 'STORE INVENTORY PARENT',
        ];

        // Logs
        $log_result = $this->helper->log($request, $arr_data_logs);

        return response()->json([
            'message' => 'Inventory records parent store successfully',
            'log_message' => $log_result
        ], Response::HTTP_OK);
    }

    /**
     * Show the form for editing the specified resource.
     */
    public function show(Request $request, string $id)
    {
        $arr_inventory = [];

        // Authorize the user
        $user = $this->helper->authorizeUser($request);
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        $inventory = InventoryModel::where('inventory_id', Crypt::decrypt($id))->first();
        if (!$inventory) {
            return response()->json(
                [
                    'message' => 'Data not found',
                ],
                Response::HTTP_NOT_FOUND
            );
        }

        foreach ($this->fillable_attr_inventorys->getFillableAttributes() as $getFillableAttribute) {
            if ($getFillableAttribute == 'inventory_id') {
                $arr_inventory[$getFillableAttribute] = Crypt::encrypt($inventory->$getFillableAttribute);
            } else if (in_array($getFillableAttribute, $this->fillable_attr_inventory_children->arrToConvertToReadableDateTime())) {
                $carbon_date = Carbon::parse($inventory->$getFillableAttribute);
                $value = $carbon_date->format('F j, Y g:i a');
                $arr_inventory[$getFillableAttribute] = $value;
            } else {
                $arr_inventory[$getFillableAttribute] = $inventory->$getFillableAttribute;
            }
        }


        return response()->json(
            [
                "message" => "Successfully Retrieve Data",
                'result' => $arr_inventory,
            ],
            Response::HTTP_OK
        );
    }

    public function showProduct(Request $request, string $id)
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
                "message" => "Successfully Retrieve Data",
                'result' => $arr_inventory_product,
            ],
            Response::HTTP_OK
        );
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(Request $request)
    {
        $arr_existing_data = [];
        $changes_for_logs = [];

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
            'items.*.inventory_id' => 'required|string',
            'items.*.name' => 'required|string|max:255',
            'items.*.category' => 'required|string|max:255',
            'items.*.eu_device' => 'required|string',
        ]);

        // Check if validation fails
        if ($validator->fails()) {
            return response()->json(['message' => $validator->errors()], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        // Add custom validation rule for unique combination of name and category
        $validator->after(function ($validator) use ($request) {
            foreach ($request->input('items') as $item) {
                $exists = InventoryModel::where('name', $item['name'])
                    ->where('category', $item['category'])
                    ->exists();

                if ($exists) {
                    $validator->errors()->add('items', 'The combination of name and category already exists.');
                }
            }
        });

        // Input User
        foreach ($request['items'] as $user_input) {
            // Validate eu_device
            $result_validate_eu_device = $this->helper->validateEuDevice($user_input['eu_device']);
            if ($result_validate_eu_device) {
                return $result_validate_eu_device;
            }

            // Check if inventory record exists
            $inventory = InventoryModel::where('inventory_id', $user_input['inventory_id'])
                ->first();
            if (!$inventory) {
                return response()->json([
                    'message' => 'Data not found'
                ], Response::HTTP_NOT_FOUND);
            }

            // Get the changes of the fields
            $result_changes_item_for_logs = $this->helper->updateLogsOldNew($inventory, $this->fillable_attr_inventorys->arrToUpdates(), $user_input, '');
            $changes_for_logs[] = [
                'inventory_id' => $user_input['inventory_id'],
                'fields' => $result_changes_item_for_logs,
            ];

            // Update Multiple Data
            $result_update_multi_data = $this->helper->arrUpdateMultipleData($inventory, $this->fillable_attr_inventorys->arrToUpdates(), $user_input, '');
            if ($result_update_multi_data) {
                return $result_update_multi_data;
            }

            $eu_device = $user_input['eu_device'];
        }

        // Check if theres Changes Logs
        $changesCheckResponse = $this->helper->checkIfTheresChangesLogs($changes_for_logs);
        if ($changesCheckResponse) {
            return $changesCheckResponse;
        }

        // Arr Data Logs
        $arr_data_logs = [
            'user_device' => $eu_device,
            'user_id' => $user->user_id,
            'is_sensitive' => 0,
            'is_history' => 0,
            'log_details' => $changes_for_logs,
            'user_action' => 'UPDATE INVENTORY PARENT',
        ];

        // Logs
        $log_result = $this->helper->log($request, $arr_data_logs);

        return response()->json([
            'message' => 'Inventory records parent update successfully',
            'log_message' => $log_result,
            'exist_data' => $arr_existing_data
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

        $inventory = InventoryModel::where('inventory_id', Crypt::decrypt($request->inventory_id))->first();
        if (!$inventory) {
            return response()->json(['message' => 'Data not found'], Response::HTTP_NOT_FOUND);
        }

        // Checking Id on other tbl if exist unset the the api
        $is_exist_id_other_tbl = $this->helper->isExistIdOtherTbl($inventory->inventory_id, $this->fillable_attr_inventorys->arrModelWithId());

        // Check if 'is_exist' is 'yes' in the first element and then unset it
        if (!empty($is_exist_id_other_tbl) && $is_exist_id_other_tbl[0]['is_exist'] == 'yes') {
            return response()->json(['message' => 'Can\'t delete because this id exist on other table'], Response::HTTP_NOT_FOUND);
        }

        foreach ($this->fillable_attr_inventorys->getFillableAttributes() as $fillable_attr_inventorys) {
            $arr_log_details['fields'][$fillable_attr_inventorys] = $inventory->$fillable_attr_inventorys;
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
            'user_action' => 'DELETE INVENTORY PARENT',
        ];

        // Logs
        $log_result = $this->helper->log($request, $arr_data_logs);

        return response()->json([
            'message' => 'Successfully created user',
            'log_message' => $log_result
        ], Response::HTTP_OK);
    }
}
