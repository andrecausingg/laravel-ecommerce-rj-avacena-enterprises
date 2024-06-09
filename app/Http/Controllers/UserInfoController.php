<?php

namespace App\Http\Controllers;

use App\Models\LogsModel;
use Illuminate\Support\Str;
use Illuminate\Http\Request;

use App\Models\UserInfoModel;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Crypt;
use App\Http\Controllers\Helper\Helper;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\Validator;
use Symfony\Component\HttpFoundation\Response;

class UserInfoController extends Controller
{
    protected $fillableAttrUserInfos, $helper;
    public function __construct(Helper $helper, UserInfoModel $fillableAttrUserInfos)
    {
        $this->helper = $helper;
        $this->fillableAttrUserInfos = $fillableAttrUserInfos;
    }

    /**
     * Display a listing of the resource.
     */
    public function index(Request $request)
    {
        $decrypted_user_infos = [];

        // Authorize the user
        $user = $this->helper->authorizeUser($request);
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        // Unset Column not needed to decrypt
        $unset_results = $this->helper->unsetColumn($this->fillableAttrUserInfos->unsetDecrypt(), $this->fillableAttrUserInfos->getFillableAttributes());

        $user_infos = UserInfoModel::get();
        foreach ($user_infos as $user_info) {
            if ($user_info) {
                $arr_user_info = $user_info->toArray();

                foreach ($unset_results as $unset_result) {
                    if (isset($arr_user_info[$unset_result])) {
                        $arr_user_info[$unset_result] = $user_info->{$unset_result} ? Crypt::decrypt($user_info->{$unset_result}) : null;
                    }
                }
                $decrypted_user_infos = $arr_user_info;
            }
        }

        return response()->json([
            'message' => 'Successfully Retrieve Data',
            'result' => $decrypted_user_infos,
        ], Response::HTTP_OK);
    }

    /**
     * Display a listing of the resource.
     */
    public function getPersonalInfo(Request $request)
    {
        $decrypted_user_infos = [];

        // Authorize the user
        $user = $this->helper->authorizeUser($request);
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        $unset_results = $this->helper->unsetColumn($this->fillableAttrUserInfos->unsetDecrypt(), $this->fillableAttrUserInfos->getFillableAttributes());


        $userInfos = UserInfoModel::where('user_id', $user->user_id)->first();
        if ($userInfos) {
            $arr_user_info = $userInfos->toArray();

            foreach ($unset_results as $unset_result) {
                if (isset($arr_user_info[$unset_result])) {
                    $arr_user_info[$unset_result] = $userInfos->{$unset_result} ? Crypt::decrypt($userInfos->{$unset_result}) : null;
                }
            }
            $decrypted_user_infos = $arr_user_info;
        }

        return response()->json(
            [
                'message' => 'Successfully Retrieve Data',
                'result' => $decrypted_user_infos,
            ],
            Response::HTTP_OK
        );
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
        $exist_user_id = UserInfoModel::where('user_id', $user->user_id)->exists();
        if ($exist_user_id) {
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
            'eu_device' => 'required|string',
        ]);

        // Check if validation fails
        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        // Validate Eu Device
        $result_validate_eu_device = $this->helper->validateEuDevice($request->eu_device);
        if ($result_validate_eu_device) {
            return $result_validate_eu_device;
        }

        DB::beginTransaction(); // Begin transaction

        try {
            // UpperCase Specific Field
            $validated_data = $this->helper->upperCaseSpecific($validator->validated(), $this->fillableAttrUserInfos->getUppercase());

            // Handle image upload and update
            if ($request->hasFile('image')) {
                $arr_data_file = [
                    'custom_folder' => 'user-info',
                    'file_image' => $request->file('image'),
                    'image_actual_extension' => $request->file('image')->getClientOriginalExtension(),
                ];
                $file_name = $this->helper->handleUploadImage($arr_data_file);
            }

            // Encrypt the data
            foreach ($validated_data as $key => $value) {
                if ($key === 'image') {
                    $validated_data[$key] = $file_name != '' ? Crypt::encrypt($file_name) : null;
                } else {
                    // Check if the value is empty
                    if ($value !== null) {
                        $validated_data[$key] = Crypt::encrypt($value);
                    }
                }
            }

            // Create UserInfoModel with encrypted data
            $user_info_create = UserInfoModel::create(array_merge(['user_id' => $user->user_id], $validated_data));
            if (!$user_info_create) {
                DB::rollBack(); // Rollback transaction
                return response()->json(['message' => 'Failed to store user information'], Response::HTTP_INTERNAL_SERVER_ERROR);
            }

            $user_info_create->update([
                'user_info_id' => 'user_info_id-'  . $user_info_create->id,
            ]);

            $log_details = [
                'fields' => $user_info_create
            ];

            // Arr Data Logs
            $arr_data_logs = [
                'user_device' => $request->eu_device,
                'user_id' => $user->user_id,
                'is_sensitive' => 1,
                'is_history' => 0,
                'log_details' => $log_details,
                'user_action' => 'STORE PERSONAL INFORMATION',
            ];

            // Logs
            $log_result = $this->helper->log($request, $arr_data_logs);
            if ($log_result->getStatusCode() !== Response::HTTP_OK) {
                DB::rollBack(); // Rollback transaction
                return $log_result;
            }

            // Commit the transaction
            DB::commit();

            return response()->json([
                'message' => 'Successfully stored user information',
                'log_message' => $log_result
            ], Response::HTTP_OK);
        } catch (\Exception $e) {
            // Rollback the transaction on any exception
            DB::rollBack();
            return response()->json(['message' => $e->getMessage()], Response::HTTP_INTERNAL_SERVER_ERROR);
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
     * Update the specified resource in storage.
     */
    public function update(Request $request)
    {
        // Initialize
        $changes_for_logs = [];
        $file_name = '';

        // Authorize the user
        $user = $this->helper->authorizeUser($request);
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
            'description_location' => 'nullable|string|max:1500',
            'eu_device' => 'required|string',
        ]);

        // Check if validation fails
        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        // Validate Eu Device
        $result_validate_eu_device = $this->helper->validateEuDevice($request->eu_device);
        if ($result_validate_eu_device) {
            return $result_validate_eu_device;
        }


        DB::beginTransaction(); // Begin transaction

        try {
            // UpperCase Specific Field
            $validated_data = $this->helper->upperCaseSpecific($validator->validated(), $this->fillableAttrUserInfos->getUppercase());

            // Retrieve the user information
            $user_info = UserInfoModel::where('user_id', $user->user_id)->first();

            // Check if user information exists
            if (!$user_info) {
                return response()->json(['message' => 'Data not found'], Response::HTTP_NOT_FOUND);
            }

            // Handle image upload and update
            if ($request->hasFile('image')) {
                $arr_data_file = [
                    'custom_folder' => 'user-info',
                    'file_image' => $request->file('image'),
                    'image_actual_extension' => $request->file('image')->getClientOriginalExtension(),
                ];
                $file_name = $this->helper->handleUploadImage($arr_data_file);
            }

            // Loop through the fields for encryption and decryption
            foreach ($this->fillableAttrUserInfos->arrToUpdates() as $arrToUpdates) {
                // Check if the key exists in the $validated_data array
                if (isset($validated_data[$arrToUpdates])) {
                    $existing_value = $user_info->$arrToUpdates !== null ? Crypt::decrypt($user_info->$arrToUpdates) : null;

                    if ($arrToUpdates != 'image') {
                        $new_value = Crypt::encrypt($validated_data[$arrToUpdates]);

                        // Check if the value has changed for logs
                        if ($existing_value != $validated_data[$arrToUpdates]) {
                            $changes_for_logs[$arrToUpdates] = [
                                'oldEnc' => $existing_value,
                                'newEnc' => $validated_data[$arrToUpdates],
                            ];
                            $user_info->{$arrToUpdates} = $new_value; // Set the new value
                        }
                    } else {
                        $new_value =  $file_name != '' ? Crypt::encrypt($file_name) : null;

                        if ($existing_value == null && $new_value != null) {
                            $changes_for_logs['image'] = [
                                'oldEnc' => $existing_value,
                                'newEnc' => $file_name,
                            ];
                        } else if ($existing_value != null && $new_value != null) {
                            $changes_for_logs['image'] = [
                                'oldEnc' => $existing_value,
                                'newEnc' => $file_name,
                            ];
                        }

                        $user_info->{$arrToUpdates} = $new_value; // Set the new value
                    }
                }
            }

            // Check if there are changes before logging
            if (empty($changes_for_logs)) {
                return response()->json(['message' => 'No changes have been made'], Response::HTTP_UNPROCESSABLE_ENTITY);
            }

            // Save the changes
            if (!$user_info->save()) {
                DB::rollBack(); // Rollback transaction
                // If the code reaches here, there was an issue saving the changes
                return response()->json(['error' => 'Failed to update user information'], Response::HTTP_INTERNAL_SERVER_ERROR);
            }

            $result_format_logs = $this->formatLogsEncData($changes_for_logs);

            $log_details = [
                'user_id' => $user->user_id,
                'fields' => $result_format_logs
            ];

            // Arr Data Logs
            $arr_data_logs = [
                'user_device' => $request->eu_device,
                'user_id' => $user->user_id,
                'is_sensitive' => 1,
                'is_history' => 0,
                'log_details' => $log_details,
                'user_action' => 'UPDATE PERSONAL INFORMATION',
            ];

            // Logs
            $log_result = $this->helper->log($request, $arr_data_logs);
            if ($log_result->getStatusCode() !== Response::HTTP_OK) {
                DB::rollBack();
                return $log_result;
            }
            
            // Commit the transaction
            DB::commit();

            return response()->json([
                'message' => 'Successfully update user information',
                'log_message' => $log_result
            ], Response::HTTP_OK);
        } catch (\Exception $e) {
            // Rollback the transaction on any exception
            DB::rollBack();
            return response()->json(['message' => $e->getMessage()], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }


    public function formatLogsEncData($changes_for_logs)
    {
        $arr = [];
        foreach ($changes_for_logs as $field => $change) {
            // Check if 'oldEnc' and 'newEnc' exist in $change before encrypting
            $encryptedOldValue = isset($change['oldEnc']) ? Crypt::encrypt($change['oldEnc']) : null;
            $encryptedNewValue = isset($change['newEnc']) ? Crypt::encrypt($change['newEnc']) : null;

            // Store the original field name and its encrypted values in $arr['fields']
            $arr[$field] = [
                'oldEnc' => $encryptedOldValue,
                'newEnc' => $encryptedNewValue,
            ];
        }

        return $arr;
    }

    /**
     * Show the form for creating a new resource.
     */
    public function create()
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

    /**
     * Show the form for editing the specified resource.
     */
    public function edit(string $id)
    {
        //
    }
}
