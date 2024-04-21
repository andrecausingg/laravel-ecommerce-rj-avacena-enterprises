<?php

namespace App\Http\Controllers;

use App\Models\LogsModel;
use Illuminate\Support\Str;
use Illuminate\Http\Request;

use App\Models\UserInfoModel;
use Jenssegers\Agent\Facades\Agent;
use Illuminate\Support\Facades\Crypt;
use App\Http\Controllers\Helper\Helper;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\Validator;
use Symfony\Component\HttpFoundation\Response;

class UserInfoController extends Controller
{
    protected $fillableAttributes, $UnsetDecrypts, $Uppercase, $helper;
    public function __construct(Helper $helper)
    {
        $userInfoModel = new UserInfoModel();
        $this->fillableAttributes = $userInfoModel->getFillableAttributes();

        $this->UnsetDecrypts = config('system.user-info.UnsetDecrypt');
        $this->Uppercase = config('system.user-info.Uppercase');
        $this->helper = $helper;
    }


    /**
     * Display a listing of the resource.
     */
    public function index(Request $request)
    {
        $decryptedUserInfos = [];

        // Authorize the user
        $user = $this->helper->authorizeUser($request);
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }


        foreach ($this->UnsetDecrypts as $UnsetDecrypt) {
            // Find the key associated with the field and unset it
            $key = array_search($UnsetDecrypt, $this->fillableAttributes);
            if ($key !== false) {
                unset($this->fillableAttributes[$key]);
            }
        }

        $userInfos = UserInfoModel::get();
        foreach ($userInfos as $userInfo) {
            if ($userInfo) {
                $userInfoArray = $userInfo->toArray();

                foreach ($this->fillableAttributes as $fillableAttribute) {
                    if (isset($userInfoArray[$fillableAttribute])) {
                        $userInfoArray[$fillableAttribute] = $userInfo->{$fillableAttribute} ? Crypt::decrypt($userInfo->{$fillableAttribute}) : null;
                    }
                }
                $decryptedUserInfos = $userInfoArray;
            }
        }

        return response()->json([
            'message' => 'Successfully Retrieve Data',
            'result' => $decryptedUserInfos,
        ], Response::HTTP_OK);
    }

    public function getPersonalInfo(Request $request)
    {
        $decryptedUserInfos = [];

        // Authorize the user
        $user = $this->helper->authorizeUser($request);
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }


        foreach ($this->UnsetDecrypts as $UnsetDecrypt) {
            // Find the key associated with the field and unset it
            $key = array_search($UnsetDecrypt, $this->fillableAttributes);
            if ($key !== false) {
                unset($this->fillableAttributes[$key]);
            }
        }

        $userInfos = UserInfoModel::where('user_id', $user->user_id)->first();
        if ($userInfos) {
            $userInfoArray = $userInfos->toArray();

            foreach ($this->fillableAttributes as $fillableAttribute) {
                if (isset($userInfoArray[$fillableAttribute])) {
                    $userInfoArray[$fillableAttribute] = $userInfos->{$fillableAttribute} ? Crypt::decrypt($userInfos->{$fillableAttribute}) : null;
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
        $user = $this->helper->authorizeUser($request);
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
            'description_location' => 'nullable|string|max:1500',
        ]);

        // Check if validation fails
        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        // Transform input data to uppercase for specified fields
        $validatedData = $validator->validated();
        foreach ($validatedData as $key => $value) {
            // Check if the field should be transformed to uppercase
            if (in_array($key, $this->Uppercase)) {
                $validatedData[$key] = strtoupper($value);
            }
        }

        // Handle image upload and update
        if ($request->hasFile('image')) {
            $customFolder = 'user-info';
            $image = $request->file('image');
            $imageActualExt = $image->getClientOriginalExtension();

            // Generate File Name
            $filename = Str::uuid() . "_" . time() . "_" . mt_rand() . "_" . Str::uuid() . "." . $imageActualExt;

            // Generate the file path within the custom folder
            $filePath = $customFolder . '/' . $filename;

            // Save on Storage
            Storage::disk('public')->put($filePath, file_get_contents($image));
        }

        // Encrypt the data
        foreach ($validatedData as $key => $value) {
            if ($key === 'image') {
                $validatedData[$key] = $filename != '' ? Crypt::encrypt($filename) : null;
            } else {
                // Check if the value is empty
                if ($value !== null) {
                    $validatedData[$key] = Crypt::encrypt($value);
                }
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
        $filename = '';

        // Authorize the user
        $user = $this->helper->authorizeUser($request);
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }


        foreach ($this->UnsetDecrypts as $UnsetDecrypt) {
            // Find the key associated with the field and unset it
            $key = array_search($UnsetDecrypt, $this->fillableAttributes);
            if ($key !== false) {
                unset($this->fillableAttributes[$key]);
            }
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
            'description_location' => 'nullable|string|max:1500',
        ]);

        // Check if validation fails
        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        // Transform input data to uppercase for specified fields
        $validatedData = $validator->validated();
        foreach ($validatedData as $key => $value) {
            // Check if the field should be transformed to uppercase
            if (in_array($key, $this->Uppercase)) {
                $validatedData[$key] = strtoupper($value);
            }
        }

        // Retrieve the user information
        $userInfo = UserInfoModel::where('user_id', $user->user_id)->first();

        // Check if user information exists
        if (!$userInfo) {
            return response()->json(['message' => 'Data not found'], Response::HTTP_NOT_FOUND);
        }

        // Handle image upload and update
        if ($request->hasFile('image')) {
            $customFolder = 'user-info';
            $image = $request->file('image');
            $imageActualExt = $image->getClientOriginalExtension();

            // Generate File Name
            $filename = Str::uuid() . "_" . time() . "_" . mt_rand() . "_" . Str::uuid() . "." . $imageActualExt;

            // Generate the file path within the custom folder
            $filePath = $customFolder . '/' . $filename;

            // Save on Storage
            Storage::disk('public')->put($filePath, file_get_contents($image));
        }

        // Loop through the fields for encryption and decryption
        foreach ($this->fillableAttributes as $field) {
            // dd($userInfo->$field);
            $existingValue = $userInfo->$field !== null ? Crypt::decrypt($userInfo->$field) : null;
            // dd($existingValue);

            if ($field != 'image') {
                $newValue = Crypt::encrypt($validatedData[$field]);

                // Check if the value has changed for logs
                if ($existingValue != $validatedData[$field]) {
                    $changesForLogs[$field] = [
                        'oldEnc' => $existingValue,
                        'newEnc' => $validatedData[$field],
                    ];
                    $userInfo->{$field} = $newValue; // Set the new value
                }
            } else {
                $newValue =  $filename != '' ? Crypt::encrypt($filename) : null;

                if ($existingValue == null && $newValue != null) {
                    $changesForLogs['image'] = [
                        'oldEnc' => $existingValue,
                        'newEnc' => $filename,
                    ];
                } else if ($existingValue != null && $newValue != null) {
                    $changesForLogs['image'] = [
                        'oldEnc' => $existingValue,
                        'newEnc' => $filename,
                    ];
                }

                $userInfo->{$field} = $newValue; // Set the new value
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
        $arr['fields'] = $logDetails;

        // Get Device Information
        $userAgent = $request->header('User-Agent');

        // Create LogsModel entry
        $log = LogsModel::create([
            'user_id' => $userId,
            'is_sensitive' => 1,
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
        $arr['fields'] = [];
        $arr['fields']['user_id'] = $userId;

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
            'is_sensitive' => 1,
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
