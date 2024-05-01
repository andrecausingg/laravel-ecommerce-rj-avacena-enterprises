<?php

namespace App\Http\Controllers\Helper;

use App\Models\LogsModel;
use Illuminate\Support\Str;
use App\Models\HistoryModel;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Http;
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
    public function transformColumnName($column)
    {
        return ucwords(str_replace('_', ' ', $column));
    }

    public function functionRelative($prefix, $apiWithPayloads, $methods, $buttonNames, $icons, $actions)
    {
        $functions = [];

        foreach ($apiWithPayloads as $key => $payload) {
            // Remove forward slash from the key
            $cleanedKey = rtrim($key, '/');

            $method = $methods[$key] ?? null;
            $functions[$cleanedKey] = [
                'api' => $prefix . $key,
                'payload' => $payload,
                'method' => $method,
                'icon' => $icons[$key],
                'button_name' => $this->upperCase($buttonNames[$key]),
                'action' => $actions[$key],
            ];
        }

        return [$functions];
    }

    public function functionsApiAccountsCrud($prefix, $apiWithPayloads, $methods, $buttonNames, $icons, $actions)
    {
        $functions = [];

        foreach ($apiWithPayloads as $key => $payload) {
            $method = $methods[$key] ?? null;
            $functions[$key] = [
                'api' => $prefix . $key,
                'payload' => $payload,
                'method' => $method,
                'icon' => $icons[$key],
                'button_name' => $this->upperCase($buttonNames[$key]),
                'action' => $actions[$key],
            ];
        }

        return $functions;
    }

    public function log($request, $arr_data_logs)
    {
        if ($arr_data_logs['is_history'] == 1) {
            $history = HistoryModel::create([
                'tbl_id' => $arr_data_logs['log_details']['fields']['user_id'],
                'tbl_name' => 'users_tbl',
                'column_name' => 'password',
                'value' => $arr_data_logs['log_details']['fields']['password'] ?? $arr_data_logs['log_details']['fields']['new_password'],
            ]);

            // Check if history creation failed
            if (!$history) {
                return response()->json(['message' => 'Failed to store history'], Response::HTTP_INTERNAL_SERVER_ERROR);
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
            return response()->json(['message' => 'Failed to store logs'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        $log_update = $log->update([
            'log_id' => 'log_id-'  . $log->id,
        ]);

        // Check if history update failed
        if (!$log_update) {
            return response()->json(['message' => 'Failed to update log ID'], Response::HTTP_INTERNAL_SERVER_ERROR);
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

        // Initialize a variable to store validation result
        $allExist = true;

        // Loop through each key
        foreach ($keys as $key) {
            if (!array_key_exists($key, $decrypt_eu_device)) {
                $allExist = false;
                break;
            }
        }

        // Return the validation result
        return $allExist ? "valid" : "invalid";
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
}
