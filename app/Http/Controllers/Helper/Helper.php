<?php

namespace App\Http\Controllers\Helper;

use App\Models\AuthModel;
use App\Models\LogsModel;
use Illuminate\Support\Str;
use App\Models\HistoryModel;
use App\Models\PaymentModel;
use Illuminate\Http\Request;
use App\Models\PurchaseModel;
use App\Models\UserInfoModel;
use Illuminate\Support\Carbon;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Http;
use App\Models\InventoryProductModel;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Storage;
use hisorange\BrowserDetect\Facade as Browser;
use Symfony\Component\HttpFoundation\Response;



class Helper
{
    // Authentication
    public function authorizeUser($request)
    {
        try {
            // Authenticate the user with the provided token
            $user = JWTAuth::parseToken()->authenticate();
            // Get the bearer token from the headers
            $bearer_token = $request->bearerToken();

            // Check if user is not found
            if (!$user) {
                return response()->json(['message' => 'User not found'], Response::HTTP_UNAUTHORIZED);
            }

            // Check if bearer token is missing
            if ($user->session_token !== $bearer_token) {
                return response()->json(['message' => 'Invalid token'], Response::HTTP_UNAUTHORIZED);
            }

            // Check if the user's session token does not match the bearer token or if the session has expired
            if ($user->session_expire_at < Carbon::now()) {
                return response()->json(['message' => 'Session Expired'], Response::HTTP_UNAUTHORIZED);
            }

            // If everything is valid, return the authenticated user
            return $user;
        } catch (\Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {
            return response()->json(['message' => 'Token expired'], Response::HTTP_UNAUTHORIZED);
        } catch (\Tymon\JWTAuth\Exceptions\TokenInvalidException $e) {
            return response()->json(['message' => 'Invalid token'], Response::HTTP_UNAUTHORIZED);
        } catch (\Tymon\JWTAuth\Exceptions\JWTException $e) {
            return response()->json(['message' => 'Failed to authenticate'], Response::HTTP_UNAUTHORIZED);
        }
    }

    // Unset column dont want to include to save on database
    public function unsetColumn($unsets, $fillableAttr)
    {
        foreach ($unsets as $unset) {
            // Find the key associated with the field and unset it
            $key = array_search($unset, $fillableAttr);
            if ($key !== false) {
                unset($fillableAttr[$key]);
            }
        }

        return $fillableAttr;
    }

    // Uppercase specific data base on validated
    public function upperCaseSpecific($validatedData, $colUpperCase)
    {
        foreach ($validatedData as $key => $value) {
            // Check if the field should be transformed to uppercase
            if (in_array($key, $colUpperCase)) {
                $validatedData[$key] = strtoupper($value);
            }
        }

        return $validatedData;
    }

    public function upperCaseValueSelectTagFilter($datas)
    {
        $arr_select_fields = [];

        foreach ($datas as $key => $value) {
            // Replace underscores with spaces and capitalize each word
            $label = ucwords(str_replace('_', ' ', strtolower($value)));
            $arr_select_fields[] = [
                'label' => $label,
                'value' => $value,
            ];
        }

        return $arr_select_fields;
    }

    // Uppercase the Word with dash -
    public function upperCase($buttonName)
    {
        if ($buttonName == '' || $buttonName == null) {
            return null;
        }
        // Remove hyphens and uppercase the string
        $upperCaseString = str_replace('-', ' ', ucfirst($buttonName));

        return $upperCaseString;
    }

    // Uppercase All the Word with dash - 
    public function transformColumnName($columns)
    {
        $arr_column = [];

        if (is_array($columns)) {
            foreach ($columns as $column) {
                $arr_column[] = ucwords(str_replace('_', ' ', $column));
            }

            return $arr_column;
        } else {
            return ucwords(str_replace('_', ' ', $columns));
        }
    }

    public function formatApi($prefix, $api_with_payloads, $method, $button_names, $icons, $actions)
    {
        $functions = [];

        foreach ($api_with_payloads as $key => $payload) {
            // Remove forward slash from the key
            $cleanedKey = rtrim($key, '/');

            $method = $method[$key] ?? null;
            $functions[$cleanedKey] = [
                'url' => $prefix . $key,
                'payload' => $payload,
                'method' => $method,
                'icon' => $icons[$key],
                'button_name' => $this->upperCase($button_names[$key]),
                'action' => $actions[$key],
            ];
        }

        return $functions[] = $functions;
    }

    public function log($request, $arr_data_logs)
    {
        if ($arr_data_logs['is_history'] == 1) {
            $history = HistoryModel::create([
                'tbl_id' => $arr_data_logs['log_details']['fields']['user_id'],
                'tbl_name' => 'users_tbl',
                'column_name' => 'password',
                'value' => !is_array($arr_data_logs['log_details']['fields']['password']) ?
                    $arr_data_logs['log_details']['fields']['password'] : (isset($arr_data_logs['log_details']['fields']['password']['new']) ?
                        $arr_data_logs['log_details']['fields']['password']['new'] :
                        null
                    ),
            ]);

            // Check if history creation failed
            if (!$history) {
                return response()->json([
                    'message' => 'Failed to store history',
                    'parameter' => $history,
                ], Response::HTTP_INTERNAL_SERVER_ERROR);
            }

            // Update history ID
            $history_update = $history->update([
                'history_id' => 'history_id-' . $history->id,
            ]);

            // Check if history update failed
            if (!$history_update) {
                return response()->json(['message' => 'Failed to update history ID'], Response::HTTP_INTERNAL_SERVER_ERROR);
            }
        }

        $log = LogsModel::create([
            'user_id' => $arr_data_logs['user_id'],
            'is_sensitive' => $arr_data_logs['is_sensitive'],
            'ip_address' => $request->ip(),
            'user_action' => strtoupper($arr_data_logs['user_action']),
            'user_device' => $arr_data_logs['user_device'] != null && $arr_data_logs['user_device'] != '' ? json_encode(Crypt::decrypt($arr_data_logs['user_device']), JSON_PRETTY_PRINT) : null,
            'details' => json_encode($arr_data_logs['log_details'], JSON_PRETTY_PRINT),
        ]);

        if (!$log) {
            return response()->json([
                'message' => 'Failed to store logs',
                'parameter' => $log,
            ], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        $log_update = $log->update([
            'log_id' => 'log_id-'  . $log->id,
        ]);

        // Check if history update failed
        if (!$log_update) {
            return response()->json([
                'message' => 'Failed to update log ID',
                'parameter' => $log_update,
            ], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        return response()->json(['message' => $arr_data_logs['is_history'] == 1 ? 'Successfully stored logs and history' : 'Successfully stored logs'], Response::HTTP_OK);
    }

    public function userDevice(Request $request)
    {
        $device = Browser::isMobile() ? 'Mobile' : (Browser::isTablet() ? 'Tablet' : 'Desktop');
        $isp_provider = $this->getUserISP($request->ip());

        $device_info = [
            'browser_name' => Browser::browserName(),
            'platform_name' => Browser::platformName(),
            'is_mobile' => Browser::isMobile(),
            'is_tablet' => Browser::isTablet(),
            'is_desktop' => Browser::isDesktop(),
            'is_bot' => Browser::isBot(),
            'device_type' => Browser::deviceType(),
            'browser_family' => Browser::browserFamily(),
            'browser_version' => Browser::browserVersion(),
            'browser_version_major' => Browser::browserVersionMajor(),
            'browser_version_minor' => Browser::browserVersionMinor(),
            'browser_version_patch' => Browser::browserVersionPatch(),
            'browser_engine' => Browser::browserEngine(),
            'platform_family' => Browser::platformFamily(),
            'platform_version' => Browser::platformVersion(),
            'platform_version_major' => Browser::platformVersionMajor(),
            'platform_version_minor' => Browser::platformVersionMinor(),
            'platform_version_patch' => Browser::platformVersionPatch(),
            'is_windows' => Browser::isWindows(),
            'is_linux' => Browser::isLinux(),
            'is_mac' => Browser::isMac(),
            'is_android' => Browser::isAndroid(),
            'device_family' => Browser::deviceFamily(),
            'device_model' => Browser::deviceModel(),
            'is_chrome' => Browser::isChrome(),
            'is_firefox' => Browser::isFirefox(),
            'is_opera' => Browser::isOpera(),
            'is_safari' => Browser::isSafari(),
            'is_ie' => Browser::isIE(),
            'is_edge' => Browser::isEdge(),
            'is_in_app' => Browser::isInApp(),
        ];

        $arr_data_device = [
            'device_use' => $device,
            'ip' => $request->ip(),
            'isp' => $isp_provider,
            'device_info' => $device_info,

        ];

        // return response()->json(['message' => 'Successfully retrieved eu', 'eu' => $arr_data_device], Response::HTTP_OK);
        return response()->json(['message' => 'Successfully retrieved eu', 'eu' => Crypt::encrypt($arr_data_device)], Response::HTTP_OK);
    }
    private function getUserISP($ip)
    {
        $response = Http::get("http://ip-api.com/json/{$ip}");

        if ($response->successful()) {
            return $response->json();
        } else {
            // Handle unsuccessful response
            return null;
        }
    }

    // Validate Eu device
    public function validateEuDevice($eu_device)
    {
        $decrypt_eu_device = Crypt::decrypt($eu_device);

        // Array of keys to check
        $keys = [
            'device_use',
            'ip',
            'isp',
            'device_info',
        ];

        // Loop through each key
        foreach ($keys as $key) {
            if (!array_key_exists($key, $decrypt_eu_device)) {
                return response()->json(['message' => 'Incorrect eu device'], Response::HTTP_UNPROCESSABLE_ENTITY);
            }
        }
    }
    public function handleUploadImage($arr_data_file)
    {
        $file_name = '';

        // Generate File Name
        $file_name = Str::uuid() . "_" . time() . "_" . mt_rand() . "_" . Str::uuid() . "." . $arr_data_file['image_actual_extension'];

        // Generate the file path within the custom folder
        $file_path = $arr_data_file['custom_folder'] . '/' . $file_name;

        // Save on Storage
        Storage::disk('public')->put($file_path, file_get_contents($arr_data_file['file_image']));

        return $file_name;
    }

    // This is for checking in index to display a button delete
    public function isExistIdOtherTbl($id, $modelAndId)
    {
        $arr_result = [];

        foreach ($modelAndId as $model => $columns) {
            foreach ($columns as $column) {
                if ($model == 'HistoryModel') {
                    $exists = HistoryModel::where($column, $id)->exists();
                    $data = HistoryModel::where($column, $id)->first();
                    if ($exists) {
                        $arr_result[] = [
                            'is_exist' => 'yes',
                            'model' => $model,
                            // 'data' => $data
                        ];
                    }
                }

                if ($model == 'LogsModel') {
                    $exists = LogsModel::where($column, $id)->exists();
                    $data = LogsModel::where($column, $id)->first();
                    if ($exists) {
                        $arr_result[] = [
                            'is_exist' => 'yes',
                            'model' => $model,
                            // 'data' => $data
                        ];
                    }
                }

                if ($model == 'PaymentModel') {
                    $exists = PaymentModel::where($column, $id)->exists();
                    $data = PaymentModel::where($column, $id)->first();
                    if ($exists) {
                        $arr_result[] = [
                            'is_exist' => 'yes',
                            'model' => $model,
                            // 'data' => $data
                        ];
                    }
                }

                if ($model == 'PurchaseModel') {
                    $exists = PurchaseModel::where($column, $id)->exists();
                    $data = PurchaseModel::where($column, $id)->first();
                    if ($exists) {
                        $arr_result[] = [
                            'is_exist' => 'yes',
                            'model' => $model,
                            // 'data' => $data
                        ];
                    }
                }

                if ($model == 'UserInfoModel') {
                    $exists = UserInfoModel::where($column, $id)->exists();
                    $data = UserInfoModel::where($column, $id)->first();
                    if ($exists) {
                        $arr_result[] = [
                            'is_exist' => 'yes',
                            'model' => $model,
                            // 'data' => $data
                        ];
                    }
                }

                if ($model == 'InventoryProductModel') {
                    $exists = InventoryProductModel::where($column, $id)->exists();
                    $data = InventoryProductModel::where($column, $id)->first();
                    if ($exists) {
                        $arr_result[] = [
                            'is_exist' => 'yes',
                            'model' => $model,
                            // 'data' => $data
                        ];
                    }
                }
            }
        }

        // Return 'notExist' if no match is found
        return $arr_result;
    }

    // Store Multiple Data
    public function arrStoreMultipleData($arr_store_fields, $user_input_data, $file_name = '')
    {

        $arr_attributes_store = [];

        foreach ($arr_store_fields as $arr_store_field) {
            if (array_key_exists($arr_store_field, $user_input_data)) {
                if ($arr_store_field === 'image') {
                    $arr_attributes_store[$arr_store_field] = $file_name;
                } else {
                    $arr_attributes_store[$arr_store_field] = $user_input_data[$arr_store_field];
                }
            }
        }

        return $arr_attributes_store;
    }

    // Update a unique I.D on store and update
    public function updateUniqueId($model, $id_to_updates, $id)
    {
        // Update the unique id
        foreach ($id_to_updates as $id_to_updates_key => $id_to_updates_value) {
            $model->update([$id_to_updates_key => $id_to_updates_value . $id]);
        }
        if (!$model->save()) {
            return response()->json(['message' => 'Failed to update unique id'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    public function arrUpdateMultipleData($model, $arr_update_fields, $user_input_data, $file_name = '')
    {
        // Update the inventory info
        foreach ($arr_update_fields as $arr_update_field) {
            if ($arr_update_field == 'image') {
                $model->$arr_update_field = $file_name;
            } else {
                $model->$arr_update_field = $user_input_data[$arr_update_field];
            }
        }
        if (!$model->save()) {
            return response()->json(['message' => 'Failed to update inventory'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    public function updateLogsOldNew($model, $arr_update_fields, $user_input_data, $file_name)
    {
        $changes_item_for_logs = [];

        foreach ($arr_update_fields as $arr_update_field) {
            $existing_value = $model->$arr_update_field ?? null;
            $new_value = $user_input_data[$arr_update_field] ?? null;

            if ($arr_update_field != 'image') {
                // Check if the value has changed
                if ($existing_value != $new_value) {
                    $changes_item_for_logs[$arr_update_field] = [
                        'old' => $existing_value,
                        'new' => $new_value,
                    ];
                }
            } else {
                $new_value =  $file_name != '' ? $file_name : null;

                if ($existing_value == null && $new_value != null) {
                    $changes_item_for_logs['image'] = [
                        'old' => $existing_value,
                        'new' => $file_name,
                    ];
                } else if ($existing_value != null && $new_value != null) {
                    $changes_item_for_logs['image'] = [
                        'old' => $existing_value,
                        'new' => $file_name,
                    ];
                }

                $model->{$arr_update_field} = $new_value; // Set the new value
            }
        }


        return $changes_item_for_logs;
    }

    public function checkIfTheresChangesLogs($changes_for_logs)
    {
        foreach ($changes_for_logs as $item) {
            if (array_key_exists('fields', $item) && is_array($item['fields']) && empty($item['fields'])) {
                return response()->json(['message' => 'No changes have been made'], Response::HTTP_UNPROCESSABLE_ENTITY);
            }
        }
    }

    public function convertReadableTimeDate($data)
    {
        // Set the timezone for Carbon to 'Asia/Manila'
        // Carbon::setToStringFormat('F j, Y g:i a');
        $carbon_date = Carbon::parse($data)->setTimezone('Asia/Manila');
        $value = $carbon_date->format('F j, Y g:i a');

        return $value;
    }

}
