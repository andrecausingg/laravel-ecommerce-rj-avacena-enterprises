<?php

namespace App\Http\Controllers;

use App\Models\HistoryModel;
use App\Models\LogsModel;
use Illuminate\Support\Str;
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
    public function index(Request $request)
    {
        $fields = config('user-info-fields.EncUserInfoFields');
        $decryptedUserInfos = [];

        // Authorize the user
        $user = $this->authorizeUser($request);

        // Check if authenticated user
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        $userInfos = UserInfoModel::get();

        foreach ($userInfos as $userInfo) {
            if ($userInfo) {
                $userInfoArray = $userInfo->toArray();

                foreach ($fields as $field) {
                    if (isset($userInfoArray[$field])) {
                        $userInfoArray[$field] = $userInfo->{$field} ? Crypt::decrypt($userInfo->{$field}) : null;
                    }
                }
                $decryptedUserInfos = $userInfoArray;
            }
        }

        return response()->json(
            [
                'message' => 'Successfully Retrieve Data',
                'result' => $decryptedUserInfos,
            ],
            Response::HTTP_OK
        );
    }

    public function getPersonalInfo(Request $request)
    {
        $fields = config('user-info-fields.EncUserInfoFields');

        // Authorize the user
        $user = $this->authorizeUser($request);

        // Check if authenticated user
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        $decryptedUserInfos = [];

        $userInfos = UserInfoModel::where('user_id', $user->user_id)->first();
        if ($userInfos) {
            $userInfoArray = $userInfos->toArray();

            foreach ($fields as $field) {
                if (isset($userInfoArray[$field])) {
                    $userInfoArray[$field] = $userInfos->{$field} ? Crypt::decrypt($userInfos->{$field}) : null;
                }
            }
            $decryptedUserInfos = $userInfoArray;
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
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(Request $request)
    {
        // Authorize the user
        $user = $this->authorizeUser($request);

        // Check if authenticated user
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        // Check if exist user
        $existHash = UserInfoModel::where('user_id', $user->user_id)->exists();
        if ($existHash) {
            return response()->json(
                [
                    'message' => 'User i.d hash already exist',
                ],
                Response::HTTP_INTERNAL_SERVER_ERROR
            );
        }

        // Validation rules
        $validator = Validator::make($request->all(), [
            'image' => $request->hasFile('image') ? 'image|mimes:jpeg,png,jpg|max:10240' : 'nullable',
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

        // Handle image upload and update
        if ($request->hasFile('image')) {
            $image = $request->file('image');
            $imageActualExt = $image->getClientOriginalExtension();

            // Generate File Name
            $filename = Str::uuid() . "_" . time() . "_" . mt_rand() . "_" . Str::uuid() . "." . $imageActualExt;

            // Save on Storage
            Storage::disk('public')->put($filename, file_get_contents($image));
        }

        // Encrypt the data
        foreach ($validator->validated() as $key => $value) {
            if ($key === 'image') {
                $validatedData[$key] = Crypt::encrypt($filename);
            } else {
                $validatedData[$key] = Crypt::encrypt($value);
            }
        }

        // Create UserInfoModel with encrypted data
        $userInfoCreate = UserInfoModel::create(array_merge(['user_id' => $user->user_id], $validatedData));
        if ($userInfoCreate) {
            $userInfoCreate->update([
                'user_info_id' => 'user_info_id-'  . $userInfoCreate->id,
            ]);

            // Store Logs
            $logResult = $this->storeLogs($request, $user->user_id, $userInfoCreate);
            return response()->json([
                'message' => 'Successfully stored user information',
                'log_message' => $logResult
            ], Response::HTTP_OK);
        } else {
            return response()->json(['message' => 'Failed to store user information'], Response::HTTP_INTERNAL_SERVER_ERROR);
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
    public function update(Request $request)
    {
        // Initialize
        $changesForLogs = [];
        $fields = config('user-info-fields.EncUserInfoFields');

        // Authorize the user
        $user = $this->authorizeUser($request);

        // Check if authenticated user
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        // Validation rules
        $validator = Validator::make($request->all(), [
            'image' => $request->hasFile('image') ? 'image|mimes:jpeg,png,jpg|max:10240' : 'nullable',
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
        $userInfo = UserInfoModel::where('user_id', $user->user_id)->first();

        // Check if user information exists
        if (!$userInfo) {
            return response()->json(['message' => 'Data not found'], Response::HTTP_NOT_FOUND);
        }

        // Handle image upload and update
        if ($request->hasFile('image')) {
            $image = $request->file('image');
            $imageActualExt = $image->getClientOriginalExtension();

            // Generate File Name
            $filename = Str::uuid() . "_" . time() . "_" . mt_rand() . "_" . Str::uuid() . "." . $imageActualExt;

            // Encrypt the new image name before saving it
            $newImageEncrypted = Crypt::encrypt($filename);

            // Log the changes for the image if it's different
            if (Crypt::decrypt($userInfo->image) !== $filename) {
                $changesForLogs['image'] = [
                    'old' => Crypt::decrypt($userInfo->image),
                    'new' => $filename,
                ];
            }

            // Save on Storage
            Storage::disk('public')->put($filename, file_get_contents($image));

            $userInfo->image = $newImageEncrypted;
        }

        // Loop through the fields for encryption and decryption
        foreach ($fields as $field) {
            try {
                // Check if the field is 'image' and it's null, skip it from the log
                if ($field == 'image' && !$request->hasFile('image')) {
                    continue;
                }

                $existingValue = $userInfo->$field ? Crypt::decrypt($userInfo->$field) : null;
                $newValue = $request->filled($field) ? Crypt::encrypt($request->input($field)) : $existingValue;

                // Check if the value has changed
                if ($existingValue != $request->input($field) && $request->input($field) != null) {
                    $changesForLogs[$field] = [
                        'oldEnc' => $existingValue,
                        'newEnc' => $request->input($field),
                    ];
                }

                // Update the user info
                $userInfo->$field = $newValue;
            } catch (\Exception $e) {
                // Log or dump information about the exception
                Log::info("Decryption error for field $field: " . $e->getMessage());
            }
        }

        // Save the changes
        if ($userInfo->save()) {
            // Check if there are changes before logging
            if (!empty($changesForLogs)) {
                // Update successful, log the changes
                $logResult = $this->updateLogs($request, $user->user_id, $changesForLogs);

                return response()->json([
                    'message' => 'Successfully update user information',
                    'log_message' => $logResult
                ], Response::HTTP_OK);
            }
            return response()->json(['message' => 'No changes have been made'], Response::HTTP_UNPROCESSABLE_ENTITY);
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

    // Store Logs
    public function storeLogs($request, $userId, $logDetails)
    {
        $arr = [];
        $arr['user_id'] = $userId;
        $arr['fields'] = $logDetails;

        // Get Device Information
        $userAgent = $request->header('User-Agent');

        // Create LogsModel entry
        $log = LogsModel::create([
            'user_id' => $userId,
            'ip_address' => $request->ip(),
            'user_action' => 'STORE PERSONAL INFORMATION',
            'user_device' => $userAgent,
            'details' => json_encode($arr, JSON_PRETTY_PRINT),
        ]);

        if ($log) {
            $log->update([
                'log_id' => 'log_id-'  . $log->id,
            ]);
        } else {
            return response()->json(['message' => 'Failed to store logs for personal information'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        return response()->json(['message' => 'Successfully stored logs for personal information'], Response::HTTP_OK);
    }

    public function updateLogs($request, $userId, $logDetails)
    {
        $arr = [];
        $arr['user_id'] = $userId;
        $arr['fields'] = [];

        // Get Device Information
        $userAgent = $request->header('User-Agent');

        foreach ($logDetails as $field => $change) {
            // Check if 'oldEnc' and 'newEnc' exist in $change before encrypting
            $encryptedOldValue = isset($change['oldEnc']) ? Crypt::encrypt($change['oldEnc']) : null;
            $encryptedNewValue = isset($change['newEnc']) ? Crypt::encrypt($change['newEnc']) : null;

            // Store the original field name and its encrypted values in $arr['fields']
            $arr['fields'][$field] = [
                'oldEnc' => $encryptedOldValue,
                'newEnc' => $encryptedNewValue,
            ];
        }

        // Create LogsModel entry
        $log = LogsModel::create([
            'user_id' => $userId,
            'ip_address' => $request->ip(),
            'user_action' => 'UPDATE PERSONAL INFORMATION',
            'user_device' => $userAgent,
            'details' => json_encode($arr, JSON_PRETTY_PRINT),
        ]);

        if ($log) {
            $log->update([
                'log_id' => 'log_id-'  . $log->id,
            ]);
        } else {
            return response()->json(['message' => 'Failed to update logs for personal information'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        return response()->json(['message' => 'Successfully update logs for personal information'], Response::HTTP_OK);
    }
}
