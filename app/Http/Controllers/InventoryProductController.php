<?php

namespace App\Http\Controllers;

use App\Models\LogsModel;
use Illuminate\Support\Str;
use Illuminate\Http\Request;
use App\Models\InventoryModel;
use App\Models\InventoryProductModel;
use App\Http\Controllers\Helper\Helper;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\Validator;
use Symfony\Component\HttpFoundation\Response;

class InventoryProductController extends Controller
{

    protected $fillAttrInventoryProducts, $unsetsTimeStamps, $unsetsStore, $helper;

    public function __construct(Helper $helper)
    {
        $InventoryProductModel = new InventoryProductModel();

        $this->fillAttrInventoryProducts = $InventoryProductModel->getFillableAttributes();
        $this->unsetsTimeStamps = config('system.a-global.Unset-Timestamp');
        $this->unsetsStore = config('system.inventory-product.UnsetStore');
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
        $filename = '';
        // Initialize an array to store all created items
        $createdItems = [];
        $arrStore = [];

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

        foreach ($request['items'] as $productUserInput) {
            // Retrieve the inventory record
            $inventory = InventoryModel::where('group_id', $productUserInput['inventory_group_id'])->first();

            // Check if inventory record exists
            if (!$inventory) {
                return response()->json(['message' => 'Parent inventory I.D not found'], Response::HTTP_NOT_FOUND);
            }

            // Handle image
            if ($productUserInput['image'] && $productUserInput['image']->hasFile('image')) {
                $customFolder = 'inventory';
                $image = $productUserInput['image'];
                $imageActualExt = $image->getClientOriginalExtension();

                $filename = Str::uuid() . "_" . time() . "_" . mt_rand() . "_" . Str::uuid() . "." . $imageActualExt;

                $filePath = $customFolder . '/' . $filename;

                Storage::disk('public')->put($filePath, file_get_contents($image));
            }

            // Unset Columns
            $unsetResults = $this->helper->unsetColumn($this->unsetsStore, $this->fillAttrInventoryProducts);
            foreach ($unsetResults as $unsetResult) {
                $arrStore[$unsetResult] = $unsetResult == 'image' ? ($filename ? $filename : null) : $productUserInput[$unsetResult];
            }

            // Store
            $created = InventoryProductModel::create($arrStore);
            if (!$created) {
                return response()->json(
                    [
                        'message' => 'Failed to store Inventory Products',
                    ],
                    Response::HTTP_INTERNAL_SERVER_ERROR
                );
            }

            // Update Id
            $lastInsertedId = $created->id;
            $created->update([
                'inventory_product_id' => 'inv_prod_id-' . $lastInsertedId,
            ]);

            // Store Created
            $createdItems[] = $created;
        }

        // Fetch Message Logs
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

        foreach ($this->unsetsTimeStamps as $unsetsTimeStamp) {
            // Find the key associated with the field and unset it
            $key = array_search($unsetsTimeStamp, $this->fillAttrInventoryProducts);
            if ($key !== false) {
                unset($this->fillAttrInventoryProducts[$key]);
            }
        }

        foreach ($request['items'] as $productUserInput) {
            // Retrieve the inventory record
            $inventory = InventoryProductModel::where('inventory_product_id', $productUserInput['inventory_product_id'])->first();

            // Check if inventory record exists
            if (!$inventory) {
                return response()->json(['message' => 'Data not found'], Response::HTTP_NOT_FOUND);
            }

            if ($productUserInput['image'] && $productUserInput['image']->hasFile('image')) {
                $customFolder = 'inventory';
                $image = $productUserInput['image'];
                $imageActualExt = $image->getClientOriginalExtension();

                $filename = Str::uuid() . "_" . time() . "_" . mt_rand() . "_" . Str::uuid() . "." . $imageActualExt;

                $filePath = $customFolder . '/' . $filename;

                Storage::disk('public')->put($filePath, file_get_contents($image));
            }

            foreach ($this->fillAttrInventoryProducts as $fillAttrInventoryProduct) {
                $existingValue = $inventory->$fillAttrInventoryProduct ?? null;
                $newValue = $productUserInput[$fillAttrInventoryProduct] ?? null;

                // Check if the value has changed
                if ($existingValue !== $newValue) {
                    $changesForLogsItem[$fillAttrInventoryProduct] = [
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
            foreach ($this->fillAttrInventoryProducts as $fillAttrInventoryProduct) {
                $inventory->$fillAttrInventoryProduct = $productUserInput[$fillAttrInventoryProduct];
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
