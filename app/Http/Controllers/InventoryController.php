<?php

namespace App\Http\Controllers;

use App\Models\LogsModel;
use Illuminate\Support\Str;
use Illuminate\Http\Request;
use App\Models\InventoryModel;
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

        if ($user->id_hash == '' || $user->id_hash == null) {
            return ['message' => 'Not authenticated user', 'status' => Response::HTTP_UNAUTHORIZED];
        }

        // Validation rules
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'category' => 'required|string|max:255',
        ]);

        // Check if validation fails
        if ($validator->fails()) {
            return ['error' => $validator->errors(), 'status' => Response::HTTP_UNPROCESSABLE_ENTITY];
        }

        // Generate UUID
        $uuid = Str::uuid();

        // Create record in the InventoryModel
        $userInfoCreate = InventoryModel::create([
            'group_product_id' => $uuid,
            'name' => $request->input('name'), // Access input directly from the request
            'category' => $request->input('category'), // Access input directly from the request
        ]);

        if ($userInfoCreate) {
            return ['message' => 'Inventory record created successfully', 'status' => Response::HTTP_CREATED];
        }

        return ['message' => 'Failed to store Inventory Parent', 'status' => Response::HTTP_INTERNAL_SERVER_ERROR];
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

        if ($user->id_hash == '' || $user->id_hash == null) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        // Validation rules
        $validator = Validator::make($request->all(), [
            'image' => 'image|mimes:jpeg,png,jpg|max:2048',
        ]);

        // Check if validation fails
        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], Response::HTTP_UNPROCESSABLE_ENTITY);
        }
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
    public function storeLogs($request, $id, $storeData)
    {
        // Get Device Information
        $userAgent = $request->header('User-Agent');

        // Define the fields to include in the logs
        $fieldsToInclude = [
            'user_id_hash', 'image', 'first_name', 'last_name', 'contact_number',
            'email', 'address_1', 'address_2', 'region_code',
            'province_code', 'city_or_municipality_code', 'region_name',
            'province_name', 'city_or_municipality_name', 'barangay',
        ];

        // Loop through the fields and add them to userInfoDetails
        foreach ($fieldsToInclude as $field) {
            $userInfoDetails[$field] = $storeData->$field;
        }

        $details = json_encode($userInfoDetails, JSON_PRETTY_PRINT);

        // Create LogsModel entry
        $logEntry = LogsModel::create([
            'product_id' => $id,
            'ip_address' => $request->ip(),
            'user_action' => 'STORE INVENTORY',
            'user_device' => $userAgent,
            'details' => $details,
        ]);

        if (!$logEntry) {
            return response()->json(['message' => 'Failed to create logs for create inventory'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }
}
