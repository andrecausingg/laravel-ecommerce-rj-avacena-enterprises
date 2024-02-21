<?php

namespace App\Http\Controllers;

use App\Models\LogsModel;
use Illuminate\Http\Request;
use App\Models\UserInfoModel;

use Illuminate\Support\Carbon;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Log;

use Jenssegers\Agent\Facades\Agent;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\Validator;
use Symfony\Component\HttpFoundation\Response;

class UserInfoController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index()
    {
        $decryptedUserInfos = [];

        $userInfos = UserInfoModel::whereNull('deleted_at')->get();

        foreach ($userInfos as $userInfo) {
            $decryptedUserInfo = [
                'id' => $userInfo && $userInfo->id ? $userInfo->id : null,
                'user_id_hash' => $userInfo && $userInfo->user_id_hash ? $userInfo->user_id_hash : null,
                'image' => $userInfo && $userInfo->image ? Crypt::decrypt($userInfo->image) : null,
                'first_name' => $userInfo && $userInfo->first_name ? Crypt::decrypt($userInfo->first_name) : null,
                'middle_name' => $userInfo && $userInfo->middle_name ? Crypt::decrypt($userInfo->middle_name) : null,
                'last_name' => $userInfo && $userInfo->last_name ? Crypt::decrypt($userInfo->last_name) : null,
                'contact_number' => $userInfo && $userInfo->contact_number ? Crypt::decrypt($userInfo->contact_number) : null,
                'email' => $userInfo && $userInfo->email ? Crypt::decrypt($userInfo->email) : null,
                'address_1' => $userInfo && $userInfo->address_1 ? Crypt::decrypt($userInfo->address_1) : null,
                'address_2' => $userInfo && $userInfo->address_2 ? Crypt::decrypt($userInfo->address_2) : null,
                'region_code' => $userInfo && $userInfo->region_code ? Crypt::decrypt($userInfo->region_code) : null,
                'province_code' => $userInfo && $userInfo->province_code ? Crypt::decrypt($userInfo->province_code) : null,
                'city_or_municipality_code' => $userInfo && $userInfo->city_or_municipality_code ? Crypt::decrypt($userInfo->city_or_municipality_code) : null,
                'region_name' => $userInfo && $userInfo->region_name ? Crypt::decrypt($userInfo->region_name) : null,
                'province_name' => $userInfo && $userInfo->province_name ? Crypt::decrypt($userInfo->province_name) : null,
                'city_or_municipality_name' => $userInfo && $userInfo->city_or_municipality_name ? Crypt::decrypt($userInfo->city_or_municipality_name) : null,
                'barangay' => $userInfo && $userInfo->barangay ? Crypt::decrypt($userInfo->barangay) : null,
                'description_location' => $userInfo && $userInfo->description_location ? Crypt::decrypt($userInfo->description_location) : null,
            ];

            $decryptedUserInfos[] = $decryptedUserInfo;
        }

        return response()->json(
            [
                'message' => 'Successfully Retrieve Data',
                'result' => $decryptedUserInfos,
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
        // Authorize the user
        $user = $this->authorizeUser($request);

        // Get Device Information
        $userAgent = $request->header('User-Agent');

        // Validation rules
        $validator = Validator::make($request->all(), [
            'image' => 'image|mimes:jpeg,png,jpg|max:10240',
            'first_name' => 'required|string|max:255',
            'middle_name' => 'nullable|string|max:255',
            'last_name' => 'required|string|max:255',
            'contact_number' => 'required|string|max:11',
            'email' => 'required|email|max:255',
            'address_1' => 'required|string|max:255',
            'address_2' => 'nullable|string|max:255',
            'region_code' => 'required|string|max:255',
            'province_code' => 'required|string|max:255',
            'city_or_municipality_code' => 'required|string|max:255',
            'region_name' => 'required|string|max:255',
            'province_name' => 'required|string|max:255',
            'city_or_municipality_name' => 'required|string|max:255',
            'barangay' => 'required|string|max:255',
            'description_location' => 'nullable|string',
        ]);

        // Check if validation fails
        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        $image = $request->file('image');
        $imageActualExt = $image->getClientOriginalExtension();
        do {
            $filename = uniqid() . "_" . time() . "_" . mt_rand() . "." . $imageActualExt;
        } while (UserInfoModel::where('image', $filename)->exists());
        Storage::disk('public')->put($filename, file_get_contents($image));

        $existHash = UserInfoModel::where('user_id_hash', $user->id_hash)->doesntExist();
        if ($existHash) {
            // Encrypt the data
            foreach ($validator->validated() as $key => $value) {
                if ($key === 'image') {
                    $validatedData[$key] = Crypt::encrypt($filename);
                } else {
                    $validatedData[$key] = Crypt::encrypt($value);
                }
            }

            // Create UserInfoModel with encrypted data
            $userInfoCreate = UserInfoModel::create(array_merge(['user_id_hash' => $user->id_hash], $validatedData));
            if (!$userInfoCreate) {
                return response()->json(
                    [
                        'message' => 'Failed to create user information',
                    ],
                    Response::HTTP_INTERNAL_SERVER_ERROR
                );
            }

            // Store Logs
            return $this->storeLogs($request, $user->id_hash, $userInfoCreate, $userAgent);
        }

        return response()->json(
            [
                'message' => 'User i.d hash already exist',
            ],
            Response::HTTP_INTERNAL_SERVER_ERROR
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
        // Authorize the user
        $user = $this->authorizeUser($request);

        // Get Device Information
        $userAgent = $request->header('User-Agent');

        // Validation rules
        $validator = Validator::make($request->all(), [
            'image' => 'image|mimes:jpeg,png,jpg|max:10240',
            'first_name' => 'required|string|max:255',
            'middle_name' => 'nullable|string|max:255',
            'last_name' => 'required|string|max:255',
            'contact_number' => 'required|string|max:11',
            'email' => 'required|email|max:255',
            'address_1' => 'required|string|max:255',
            'address_2' => 'nullable|string|max:255',
            'region_code' => 'required|string|max:255',
            'province_code' => 'required|string|max:255',
            'city_or_municipality_code' => 'required|string|max:255',
            'region_name' => 'required|string|max:255',
            'province_name' => 'required|string|max:255',
            'city_or_municipality_name' => 'required|string|max:255',
            'barangay' => 'required|string|max:255',
            'description_location' => 'nullable|string',
        ]);

        // Check if validation fails
        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        // Retrieve the user information
        $userInfo = UserInfoModel::where('user_id_hash', $user->id_hash)->first();

        // Check if user information exists
        if (!$userInfo) {
            return response()->json(['error' => 'User not found'], Response::HTTP_NOT_FOUND);
        }

        // Initialize an array to store changes for logging
        $changesForLogs = [];

        // Handle image upload and update
        // Track changes for logging only if the image has changed
        if ($request->hasFile('image')) {
            $image = $request->file('image');
            $imageActualExt = $image->getClientOriginalExtension();
            do {
                // Decrypt the existing image name
                $existingImage = $userInfo->image ? Crypt::decrypt($userInfo->image) : null;

                $filename = uniqid() . "_" . time() . "_" . mt_rand() . "." . $imageActualExt;
            } while (UserInfoModel::where('image', Crypt::encrypt($filename))->exists());

            // Check if the image has changed
            if ($existingImage !== $filename) {
                // Encrypt the new image name before saving it
                $userInfo->image = Crypt::encrypt($filename);

                // Save the image file
                Storage::disk('public')->put($filename, file_get_contents($image));

                // Log the changes for image
                $changesForLogs['image'] = [
                    'old' => $existingImage,
                    'new' => $filename,
                ];
            }
        }

        // Define the fields to loop through
        $fields = [
            'first_name', 'middle_name', 'last_name', 'contact_number',
            'email', 'address_1', 'address_2', 'region_code',
            'province_code', 'city_or_municipality_code', 'region_name',
            'province_name', 'city_or_municipality_name', 'barangay',
            'description_location',
        ];

        // Loop through the fields for encryption and decryption
        foreach ($fields as $field) {
            try {
                $existingValue = $userInfo->$field ? Crypt::decrypt($userInfo->$field) : null;
                $newValue = $request->filled($field) ? Crypt::encrypt($request->input($field)) : $existingValue;

                // Check if the value has changed
                if ($newValue !== $existingValue) {
                    $changesForLogs[$field] = [
                        'old' => $existingValue,
                        'new' => $request->input($field),
                    ];
                }

                // Update the user info
                $userInfo->$field = $newValue;
            } catch (\Exception $e) {
                // Log or dump information about the exception
                Log::info("Decryption error for field $field: " . $e->getMessage());
            }
        }

        // Remove fields where old and new values are the same
        $changesForLogs = array_filter($changesForLogs, function ($change) {
            return $change['old'] !== $change['new'];
        });

        // Save the changes
        if ($userInfo->save()) {
            // Check if there are changes before logging
            if (!empty($changesForLogs)) {
                // Update successful, log the changes
                $this->updateLogs($request, $user->id_hash, $userInfo, $userAgent, $changesForLogs);
            }

            return response()->json(['message' => 'User information updated successfully'], Response::HTTP_OK);
        }

        // If the code reaches here, there was an issue saving the changes
        return response()->json(['error' => 'Failed to update user information'], Response::HTTP_INTERNAL_SERVER_ERROR);
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
    }

    public function showDeviceInfo()
    {
        // Get the user agent instance
        $agent = new Agent();

        // Check if the user is using a mobile device
        if (Agent::isMobile()) {
            // Get the device name
            $deviceName = Agent::device();

            // Get the platform (Android, iOS, etc.)
            $platform = Agent::platform();

            // Now you can use $deviceName and $platform as needed
            // ...
        } else {
            // The user is not on a mobile device
            // ...
        }

        // Access device, browser, and operating system information
        // $device = $agent->device();
        // $browser = $agent->browser();
        // $platform = $agent->platform();
        // // Return the information
        // return response()->json([
        //     'device' => $device,
        //     'browser' => $browser,
        //     'platform' => $platform,
        // ]);
    }

    // GLOBAL CODE
    public function storeLogs(Request $request, $idHash, $userInfoData, $userAgent)
    {
        $userInfoDetails = [
            'message' => 'Store a user information with the following details:',
            'user_id_hash' => $userInfoData->user_id_hash,
            'first_name' => $userInfoData->first_name,
            'last_name' => $userInfoData->last_name,
            'contact_number' => $userInfoData->contact_number,
            'email' => $userInfoData->email,
            'address_1' => $userInfoData->address_1,
            'address_2' => $userInfoData->address_2,
            'region_code' => $userInfoData->region_code,
            'province_code' => $userInfoData->province_code,
            'city_or_municipality_code' => $userInfoData->city_or_municipality_code,
            'region_name' => $userInfoData->region_name,
            'province_name' => $userInfoData->province_name,
            'city_or_municipality_name' => $userInfoData->city_or_municipality_name,
            'barangay' => $userInfoData->barangay,
        ];

        $details = json_encode($userInfoDetails, JSON_PRETTY_PRINT);

        // Create LogsModel entry
        $logEntry = LogsModel::create([
            'user_id_hash' => $idHash,
            'ip_address' => $request->ip(),
            'user_action' => 'CREATE USER INFORMATION',
            'user_device' => $userAgent,
            'details' => $details,
        ]);

        if (!$logEntry) {
            return response()->json(
                [
                    'message' => 'Failed to create logs for create user info',
                ],
                Response::HTTP_OK
            );
        }

        return response()->json(
            [
                'message' => 'Successfully create logs for create user info',
            ],
            Response::HTTP_OK
        );
    }

    public function updateLogs(Request $request, $idHash, $userInfoData, $userAgent, $changesForLogs)
    {
        // Create a log entry for changed fields
        $logDetails = [
            'message' => 'Update user information with the following changes:',
            'user_id_hash' => $userInfoData->user_id_hash,
            'changed_fields' => $changesForLogs,
        ];

        $details = json_encode($logDetails, JSON_PRETTY_PRINT);

        // Create LogsModel entry
        $logEntry = LogsModel::create([
            'user_id_hash' => $idHash,
            'ip_address' => $request->ip(),
            'user_action' => 'UPDATE USER INFORMATION',
            'user_device' => $userAgent,
            'details' => $details,
        ]);

        if (!$logEntry) {
            return response()->json(['error' => 'Failed to create logs'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        return response()->json(['message' => 'Successfully created logs'], Response::HTTP_OK);
    }
}
